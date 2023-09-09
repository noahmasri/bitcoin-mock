//! Este modulo contiene todos los errores personalizados a usar en las diversas funciones.
//! Tiene mappeados distintos errores de las librerias standard
use indicatif::style::TemplateError;
use std::array::TryFromSliceError;
use std::convert::Infallible;
use std::io::{Error, ErrorKind};
use std::net::AddrParseError;
use std::num::{ParseIntError, TryFromIntError};
use std::sync::mpsc::{self, RecvError, SendError};
use std::sync::{MutexGuard, PoisonError};

use crate::interface::graphics;

#[derive(Debug)]
pub enum ConfigurationError {
    InvalidPath,
    NoPermissions,
    RepeatedArguments,
    MissingArguments,
    CorruptFile,
    InvalidFieldName,
    InvalidIP,
    ExpectedInteger,
    InvalidFormat,
}

impl From<Error> for ConfigurationError {
    fn from(err: Error) -> Self {
        match err.kind() {
            ErrorKind::NotFound => ConfigurationError::InvalidPath,
            ErrorKind::PermissionDenied => ConfigurationError::NoPermissions,
            ErrorKind::UnexpectedEof => ConfigurationError::CorruptFile,
            ErrorKind::InvalidData => ConfigurationError::ExpectedInteger,
            _ => ConfigurationError::InvalidFieldName,
        }
    }
}

impl From<ParseIntError> for ConfigurationError {
    fn from(_: ParseIntError) -> Self {
        ConfigurationError::InvalidFormat
    }
}

impl From<AddrParseError> for ConfigurationError {
    fn from(_: AddrParseError) -> Self {
        ConfigurationError::InvalidIP
    }
}

#[derive(Debug)]
pub enum SocketError {
    InputOutputError,
    DomainNotFound,
    UnavailableAddress,
}

impl From<Error> for SocketError {
    fn from(err: Error) -> Self {
        match err.kind() {
            ErrorKind::NotFound => SocketError::DomainNotFound,
            ErrorKind::InvalidInput => SocketError::UnavailableAddress, // if the given address is not a valid IPv4 or IPv6 address or if the given port is not a valid port number.
            _ => SocketError::InputOutputError, //  for other I/O errors that might occur during the address resolution process.
        }
    }
}

impl From<AddrParseError> for SocketError {
    fn from(_: AddrParseError) -> Self {
        SocketError::DomainNotFound // if the given address string is not a valid address.
    }
}

#[derive(Debug)]
pub enum MessageError {
    InvalidTransaction,
    MissingCoinbaseTx,
    IncompleteMessage,
    ExpectedVerack,
    InvalidVersionMessage,
    ExpectedHeaders,
    CouldntHash,
    ErrorWhileParsing,
    InvalidMerkleBlockMessage,
    ExpectedBlock,
    CouldntSendMessage,
    InvalidBlock,
    CouldntGetIp,
}

impl From<Error> for MessageError {
    fn from(err: Error) -> Self {
        match err.kind() {
            ErrorKind::UnexpectedEof => MessageError::IncompleteMessage,
            ErrorKind::BrokenPipe | ErrorKind::WouldBlock | ErrorKind::ConnectionAborted => {
                MessageError::CouldntSendMessage
            }
            _ => MessageError::ExpectedVerack,
        }
    }
}

impl From<bitcoin_hashes::Error> for MessageError {
    fn from(_e: bitcoin_hashes::Error) -> Self {
        MessageError::CouldntHash
    }
}
impl From<TryFromSliceError> for MessageError {
    fn from(_e: TryFromSliceError) -> Self {
        MessageError::ErrorWhileParsing
    }
}
impl From<TryFromIntError> for MessageError {
    fn from(_e: TryFromIntError) -> Self {
        MessageError::ErrorWhileParsing
    }
}
impl From<UtxoError> for MessageError {
    fn from(_e: UtxoError) -> Self {
        MessageError::IncompleteMessage
    }
}
impl From<local_ip_address::Error> for MessageError {
    fn from(_e: local_ip_address::Error) -> Self {
        MessageError::CouldntGetIp
    }
}

#[derive(Debug)]
pub enum HandshakeError {
    JoinError,
    FailedToLock,
    CouldntConnectToPeers,
}

impl<T> From<PoisonError<MutexGuard<'_, T>>> for HandshakeError {
    fn from(_error: PoisonError<MutexGuard<'_, T>>) -> Self {
        HandshakeError::FailedToLock
    }
}

#[derive(Debug)]

pub enum DownloadError {
    MessageNotRequested,
    ErrorWhileParsing,
    ConnectionFailed,
    CloneFailed,
    EofEncountered,
    InvalidPath,
    FilePermissionDenied,
    CorruptFile,
    InvalidBlock,
    HandshakeFailed,
    FailedToCheckUserInfo,
    UnknownMessageError,
}

impl<T> From<SendError<T>> for DownloadError {
    fn from(_err: SendError<T>) -> Self {
        DownloadError::ConnectionFailed
    }
}

impl From<RecvError> for DownloadError {
    fn from(_err: RecvError) -> Self {
        DownloadError::ConnectionFailed
    }
}

impl From<Error> for DownloadError {
    fn from(err: Error) -> Self {
        match err.kind() {
            ErrorKind::NotFound => DownloadError::InvalidPath,
            ErrorKind::PermissionDenied => DownloadError::FilePermissionDenied,
            ErrorKind::InvalidData => DownloadError::ErrorWhileParsing,
            ErrorKind::Other => DownloadError::CorruptFile,
            ErrorKind::UnexpectedEof => DownloadError::EofEncountered,
            _ => DownloadError::UnknownMessageError,
        }
    }
}

impl<T> From<PoisonError<MutexGuard<'_, T>>> for DownloadError {
    fn from(_error: PoisonError<MutexGuard<'_, T>>) -> Self {
        DownloadError::FailedToCheckUserInfo
    }
}

impl From<MessageError> for DownloadError {
    fn from(error: MessageError) -> Self {
        match error {
            MessageError::ExpectedHeaders => DownloadError::MessageNotRequested,
            MessageError::IncompleteMessage => DownloadError::EofEncountered,
            MessageError::InvalidTransaction
            | MessageError::ExpectedBlock
            | MessageError::InvalidBlock => DownloadError::InvalidBlock,
            _ => DownloadError::UnknownMessageError,
        }
    }
}

impl From<HandshakeError> for DownloadError {
    fn from(_error: HandshakeError) -> Self {
        DownloadError::HandshakeFailed
    }
}

impl From<SocketError> for DownloadError {
    fn from(_error: SocketError) -> Self {
        DownloadError::ConnectionFailed
    }
}

impl From<TemplateError> for DownloadError {
    fn from(_error: TemplateError) -> Self {
        DownloadError::UnknownMessageError
    }
}

#[derive(Debug)]
pub enum MerkleError {
    NoTXsToMerkle,
    WrongMerkleRootHash,
    TxIdNotFound,
    ErrorInProofPath,
}

impl From<MerkleError> for MessageError {
    fn from(_: MerkleError) -> Self {
        MessageError::MissingCoinbaseTx
    }
}

#[derive(Debug)]
pub enum UtxoError {
    CouldntObtainPkHash,
    UnexpectedError,
    FailedToReceiveTxInfo,
}

impl From<TryFromSliceError> for UtxoError {
    fn from(_e: TryFromSliceError) -> Self {
        UtxoError::CouldntObtainPkHash
    }
}

impl From<Vec<u8>> for UtxoError {
    fn from(_e: Vec<u8>) -> Self {
        UtxoError::CouldntObtainPkHash
    }
}

impl From<Error> for UtxoError {
    fn from(_e: Error) -> Self {
        UtxoError::FailedToReceiveTxInfo
    }
}

#[derive(Debug)]
pub enum NodeError {
    CouldntConnectToLocal,
    UnableToJoinHandles,
    UnavailableorInvalidAddress,
    InputOutputError,
    UnknownRequest,
    ConnectionAborted,
    ExpectedHandshake,
    WalletAlreadyConnected,
    FailedToLock,
    UnableToConnectToPeers,
    CouldNotDownloadBlocks,
    CouldNotFetchAddrs,
    CouldNotVerifyPoi,
}

impl From<std::io::Error> for NodeError {
    fn from(err: std::io::Error) -> Self {
        match err.kind() {
            ErrorKind::AddrInUse | ErrorKind::AddrNotAvailable | ErrorKind::InvalidInput => {
                NodeError::UnavailableorInvalidAddress
            }
            ErrorKind::PermissionDenied | ErrorKind::ConnectionRefused => {
                NodeError::CouldntConnectToLocal
            }
            ErrorKind::UnexpectedEof => NodeError::ExpectedHandshake,
            _ => NodeError::InputOutputError,
        }
    }
}

impl<T> From<PoisonError<MutexGuard<'_, T>>> for NodeError {
    fn from(_error: PoisonError<MutexGuard<'_, T>>) -> Self {
        NodeError::FailedToLock
    }
}

impl From<MessageError> for NodeError {
    fn from(e: MessageError) -> Self {
        match e {
            MessageError::IncompleteMessage => NodeError::ConnectionAborted,
            _ => NodeError::ExpectedHandshake,
        }
    }
}

impl From<HandshakeError> for NodeError {
    fn from(_: HandshakeError) -> Self {
        NodeError::UnableToConnectToPeers
    }
}

impl From<DownloadError> for NodeError {
    fn from(_: DownloadError) -> Self {
        Self::CouldNotDownloadBlocks
    }
}

impl From<SocketError> for NodeError {
    fn from(_: SocketError) -> Self {
        Self::CouldNotFetchAddrs
    }
}

#[derive(Debug)]
pub enum InterfaceError {
    CouldntCreateInterface,
    CouldntRequestPoi,
    ErrorWhileParsing,
    CouldSendMessage,
    CouldntModifyInterface,
    LostCommunicationToGUI,
    LostCommunicationToHandler,
    WrongDataType,
    CouldntAccessRequiredWallet,
    CouldntGetRequestedInfo,
    InvalidReques,
}
impl<T> From<PoisonError<MutexGuard<'_, T>>> for InterfaceError {
    fn from(_error: PoisonError<MutexGuard<'_, T>>) -> Self {
        InterfaceError::CouldntAccessRequiredWallet
    }
}

impl From<TryFromSliceError> for InterfaceError {
    fn from(_e: TryFromSliceError) -> Self {
        InterfaceError::ErrorWhileParsing
    }
}
impl From<TryFromIntError> for InterfaceError {
    fn from(_e: TryFromIntError) -> Self {
        InterfaceError::ErrorWhileParsing
    }
}
impl From<bitcoin_hashes::hex::Error> for InterfaceError {
    fn from(_e: bitcoin_hashes::hex::Error) -> Self {
        InterfaceError::ErrorWhileParsing
    }
}
impl From<hex::FromHexError> for InterfaceError {
    fn from(_e: hex::FromHexError) -> Self {
        InterfaceError::ErrorWhileParsing
    }
}

impl From<mpsc::SendError<graphics::ToGraphic>> for InterfaceError {
    fn from(_e: SendError<graphics::ToGraphic>) -> Self {
        InterfaceError::CouldSendMessage
    }
}
impl From<RecvError> for InterfaceError {
    fn from(_e: RecvError) -> Self {
        InterfaceError::LostCommunicationToGUI
    }
}

impl From<Vec<u8>> for InterfaceError {
    fn from(_e: Vec<u8>) -> Self {
        InterfaceError::WrongDataType
    }
}

impl From<ParseIntError> for InterfaceError {
    fn from(_e: ParseIntError) -> Self {
        InterfaceError::WrongDataType
    }
}
impl From<WalletError> for InterfaceError {
    fn from(_e: WalletError) -> Self {
        InterfaceError::CouldntGetRequestedInfo
    }
}

impl From<mpsc::SendError<graphics::FromGraphic>> for InterfaceError {
    fn from(_e: SendError<graphics::FromGraphic>) -> Self {
        InterfaceError::LostCommunicationToHandler
    }
}

impl From<gtk::Widget> for InterfaceError {
    fn from(_e: gtk::Widget) -> Self {
        InterfaceError::CouldntModifyInterface
    }
}

#[derive(Debug)]
pub enum WalletError {
    CouldntGenerateKey,
    CouldntGeneratePKScript,
    CouldntGenerateInputOutpoint,
    NotEnoughBalance,
    CouldntGetOutpoint,
    InvalidOutputAddress,
    UnexpectedErrorGeneratingAddress,
    CouldntBuildMessage,
    CouldntConnectToNode,
    CouldntLock,
    ErrorCommunicatingToUI,
    CouldntFindTx,
}
impl From<SendError<graphics::ToGraphic>> for WalletError {
    fn from(_e: SendError<graphics::ToGraphic>) -> Self {
        WalletError::ErrorCommunicatingToUI
    }
}
impl From<InterfaceError> for WalletError {
    fn from(_e: InterfaceError) -> Self {
        WalletError::ErrorCommunicatingToUI
    }
}
impl From<RecvError> for WalletError {
    fn from(_e: RecvError) -> Self {
        WalletError::ErrorCommunicatingToUI
    }
}

impl From<TryFromSliceError> for WalletError {
    fn from(_e: TryFromSliceError) -> Self {
        WalletError::CouldntGenerateInputOutpoint
    }
}

impl From<std::io::Error> for WalletError {
    fn from(_: Error) -> Self {
        WalletError::CouldntConnectToNode
    }
}
impl From<secp256k1::Error> for WalletError {
    fn from(e: secp256k1::Error) -> Self {
        match e {
            secp256k1::Error::InvalidMessage => WalletError::CouldntBuildMessage,
            _ => WalletError::CouldntGenerateKey,
        }
    }
}

impl From<Infallible> for WalletError {
    fn from(_e: Infallible) -> Self {
        WalletError::CouldntGetOutpoint
    }
}

impl From<Vec<u8>> for WalletError {
    fn from(_e: Vec<u8>) -> Self {
        WalletError::InvalidOutputAddress
    }
}

impl From<bs58::decode::Error> for WalletError {
    fn from(_e: bs58::decode::Error) -> Self {
        WalletError::CouldntGenerateKey
    }
}
impl From<bs58::encode::Error> for WalletError {
    fn from(_e: bs58::encode::Error) -> Self {
        WalletError::UnexpectedErrorGeneratingAddress
    }
}
impl<T> From<PoisonError<MutexGuard<'_, T>>> for WalletError {
    fn from(_error: PoisonError<MutexGuard<'_, T>>) -> Self {
        WalletError::CouldntLock
    }
}
