//! Este modulo contiene todo el protocolo de mensajes entre un Wallet y un Nodo.
//! Contiene todas las funciones que permiten que se pueda pasar de los mensajes
//! en bytes a la estructura y de la estructura a bytes.

use crate::{
    server::utxos::UtxoInfo,
    utils::compact_size::{make_compact, parse_compact},
    utils::errors::MessageError,
    utils::tx::Transaction,
};
use std::io::Read;

/// Mensajes del protocolo creado para la comunicacion del nodo y nuestra wallet
pub struct WalletMessage {
    header: WalletMessageHeader,
    payload: Payload,
}

impl WalletMessage {
    /// Crea un mensaje dado un determinado payload
    #[must_use]
    pub fn new(payload: Payload) -> Self {
        let header = match payload {
            Payload::ConnectToNode(_p) => WalletMessageHeader::new("bindwallet\0\0"),
            Payload::AnnounceTx(_tx) => WalletMessageHeader::new("incomingtx\0\0"),
            Payload::AnnounceBlockInclusion(_inc) => WalletMessageHeader::new("blockinclude"),
            Payload::GetUtxo(_req) => WalletMessageHeader::new("getutxo\0\0\0\0\0"),
            Payload::EndConnection(_id) => WalletMessageHeader::new("endconnect\0\0"),
            Payload::SendUtxo(set) => {
                let header = WalletMessageHeader::new("sendutxo\0\0\0\0");
                return WalletMessage {
                    header,
                    payload: Payload::SendUtxo(set),
                };
            }
            Payload::CreateTx(tx) => {
                let header = WalletMessageHeader::new("createtx\0\0\0\0");
                return WalletMessage {
                    header,
                    payload: Payload::CreateTx(tx),
                };
            }
            Payload::PoiRequest(req) => {
                let header = WalletMessageHeader::new("poirequest\0\0");
                return WalletMessage {
                    header,
                    payload: Payload::PoiRequest(req),
                };
            }

            Payload::PoiAnswer(inclusion) => {
                let header = WalletMessageHeader::new("poianswer\0\0\0");
                return WalletMessage {
                    header,
                    payload: Payload::PoiAnswer(inclusion),
                };
            }

            Payload::PoiError => {
                let header = WalletMessageHeader::new("poianswer\0\0\0");
                return WalletMessage {
                    header,
                    payload: Payload::PoiError,
                };
            }
        };
        WalletMessage { header, payload }
    }

    /// Traduccion a bytes del mensaje, usado para enviarlo por un stream.
    #[must_use]
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend(self.header.as_bytes());
        bytes.extend(self.payload.as_bytes());
        bytes
    }
}

/// Header de los mensajes de nuestro protocolo, contiene el nombre del comando a ejecutar para
/// poder identificarlo cuando se recibe. Todos los nombres tienen un largo de 12 bytes
pub struct WalletMessageHeader {
    command_name: Vec<u8>,
}

impl WalletMessageHeader {
    /// Genera un header desde una variable que implementa el trait read
    /// # Errors
    /// * No se puede leer del stream la cantidad de bytes pedida. El error que devuelve es `MessageError::IncompleteMessage`
    pub fn from_reader(stream: &mut dyn Read) -> Result<Self, MessageError> {
        let mut buf_command_name: [u8; 12] = [0; 12];
        stream.read_exact(&mut buf_command_name)?;
        Ok(Self {
            command_name: buf_command_name.to_vec(),
        })
    }

    /// Creacion del header dado un identificador
    fn new(command_name: &str) -> Self {
        let mut command_bytes = vec![0; 12];
        command_bytes[..command_name.len()].copy_from_slice(command_name.as_bytes());
        Self {
            command_name: command_bytes,
        }
    }

    /// Devuelve el nombre del mensaje
    #[must_use]
    pub fn message_name(&self) -> String {
        let vec_char: Vec<char> = self.command_name.iter().map(|&x| x as char).collect();
        let string_data: String = vec_char.into_iter().collect();
        string_data
    }

    /// Traduccion a bytes del header para poder enviarlos por un stream
    #[must_use]
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();
        buf.extend(self.command_name.clone());
        buf
    }
}

/// El payload del protocolo nodo/wallet
/// Define los distintos tipos.
pub enum Payload {
    ConnectToNode(WalletId),
    AnnounceTx(IncomingTx),
    AnnounceBlockInclusion(BlockInclusion),
    GetUtxo(WalletId),
    SendUtxo(UtxoResponse),
    CreateTx(Transaction),
    PoiRequest(POIRequest),
    PoiAnswer(POIAnswer),
    EndConnection(WalletId),
    PoiError,
}

impl Payload {
    /// Traduce el Payload a su formato en bytes
    #[must_use]
    pub fn as_bytes(&self) -> Vec<u8> {
        match self {
            Self::ConnectToNode(connection_payload) => connection_payload.as_bytes(),
            Self::AnnounceTx(tx_announcement) => tx_announcement.as_bytes(),
            Self::AnnounceBlockInclusion(inclusion_announcement) => {
                inclusion_announcement.as_bytes()
            }
            Self::GetUtxo(utxo_request) => utxo_request.as_bytes(),
            Self::SendUtxo(utxo_response) => utxo_response.as_bytes(),
            Self::CreateTx(tx) => tx.as_bytes(),
            Self::PoiRequest(poi_request) => poi_request.as_bytes(),
            Self::PoiAnswer(poi_answer) => poi_answer.as_bytes(),
            Self::PoiError => 1_u8.to_le_bytes().to_vec(),
            Self::EndConnection(id) => id.pubkey_hash.to_vec(),
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq)]
/// Contiene el hash de la clave publica de la wallet que realiza el request
pub struct WalletId {
    pubkey_hash: [u8; 20],
}

impl WalletId {
    fn as_bytes(&self) -> Vec<u8> {
        self.pubkey_hash.to_vec()
    }

    /// Recibe la clave publica en formato slice y la asigna a una estructura de Id
    #[must_use]
    pub fn new(pk_hash: [u8; 20]) -> WalletId {
        Self {
            pubkey_hash: pk_hash,
        }
    }

    /// Genera un `WalletId` desde una variable que implementa el trait read
    /// # Errors
    /// * No se puede leer del stream la cantidad de bytes pedida. El error que devuelve es `MessageError::IncompleteMessage`
    pub fn from_reader(stream: &mut dyn Read) -> Result<Self, MessageError> {
        let mut buf_pkhash: [u8; 20] = [0; 20];
        stream.read_exact(&mut buf_pkhash)?;
        Ok(Self {
            pubkey_hash: buf_pkhash,
        })
    }

    /// Devuelve el hash de la clave publica
    #[must_use]
    pub fn get_public_key_hash(&self) -> [u8; 20] {
        self.pubkey_hash
    }
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub struct IncomingTx {
    /// transaction hash
    pub txid: [u8; 32],
    /// output index concerning the wallet
    pub index: u32,
    /// amount transfered to him
    pub value: i64,
}

impl IncomingTx {
    /// Crea una nueva instancia del struct `IncomingTx` y lo devuelve.
    #[must_use]
    pub fn new(txid: [u8; 32], index: u32, value: i64) -> Self {
        IncomingTx { txid, index, value }
    }

    /// Crea una nueva instancia del struct `IncomingTx` por medio del stream
    /// que recibe por parametro.
    ///
    /// # Errors
    /// * al intentar leer del stream, no se encuentra la cantidad de bytes pedida. El error obtenido
    /// es un `MessageError::IncompleteMessage`
    pub fn from_reader(stream: &mut dyn Read) -> Result<Self, MessageError> {
        let mut buf_tx_id: [u8; 32] = [0; 32];
        let mut buf_index: [u8; 4] = [0; 4];
        let mut buf_value: [u8; 8] = [0; 8];
        stream.read_exact(&mut buf_tx_id)?;
        stream.read_exact(&mut buf_index)?;
        stream.read_exact(&mut buf_value)?;

        Ok(IncomingTx::new(
            buf_tx_id,
            <u32>::from_le_bytes(buf_index),
            <i64>::from_le_bytes(buf_value),
        ))
    }

    /// Traduce el struct a formato bytes para poder enviarlo por un stream
    #[must_use]
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.txid);
        buf.extend_from_slice(&self.index.to_le_bytes());
        buf.extend_from_slice(&self.value.to_le_bytes());
        buf
    }
}

#[derive(Copy, Clone)]
/// Contiene el id de la tx y el bloque al que se la incluyo.
pub struct BlockInclusion {
    pub txid: [u8; 32],
    pub block_height: u32,
}

impl BlockInclusion {
    /// Crea una nueva instancia del struct `BlockInclusion` y lo devuelve.
    #[must_use]
    pub fn new(txid: [u8; 32], height: u32) -> Self {
        Self {
            txid,
            block_height: height,
        }
    }

    /// Devuelve el txid del `BlockInclusion`.
    #[must_use]
    pub fn txid(&self) -> [u8; 32] {
        self.txid
    }

    /// Crea una nueva instancia del struct `IncomingTx` por medio del stream
    /// que recibe por parametro.
    ///
    /// # Errors
    /// * al intentar leer del stream, no se encuentra la cantidad de bytes pedida. El error obtenido
    /// es un `MessageError::IncompleteMessage`
    pub fn from_reader(stream: &mut dyn Read) -> Result<Self, MessageError> {
        let mut buf_tx_id: [u8; 32] = [0; 32];
        let mut buf_height: [u8; 4] = [0; 4];

        stream.read_exact(&mut buf_tx_id)?;
        stream.read_exact(&mut buf_height)?;

        Ok(BlockInclusion::new(
            buf_tx_id,
            <u32>::from_le_bytes(buf_height),
        ))
    }

    /// Traduce el Payload a su formato en bytes
    #[must_use]
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.txid);
        buf.extend_from_slice(&self.block_height.to_le_bytes());
        buf
    }
}

/// Contiene informacion que envia el nodo, necesaria para actualizar el set de utxo de la wallet.
/// Es solicitado cuando el wallet envia un `UtxoRequest`.
pub struct UtxoResponse {
    pub count: usize,
    pub utxos: Vec<UtxoInfo>,
}

/// Traduccion del struct a bytes.
impl UtxoResponse {
    fn as_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend(make_compact(self.count));
        for utxo in &self.utxos {
            buf.extend(utxo.as_bytes());
        }
        buf
    }

    /// Creacion del payload en base a un vector de `UtxoInfo`.
    #[must_use]
    pub fn new(utxos: Vec<UtxoInfo>) -> Self {
        Self {
            count: utxos.len(),
            utxos,
        }
    }

    /// Crea una nueva instancia del struct `UtxoResponse` por medio delstream
    /// que recibe por parametro.
    ///
    /// # Errors
    /// * al intentar leer del stream, no se encuentra la cantidad de bytes pedida. El error obtenido
    /// es un `MessageError::IncompleteMessage`
    pub fn from_reader(stream: &mut dyn Read) -> Result<Self, MessageError> {
        let count = parse_compact(stream)?;
        let mut utxos = Vec::new();
        for _ in 0..count {
            utxos.push(UtxoInfo::from_bytes(stream)?);
        }
        Ok(Self { count, utxos })
    }
}

/// Contiene datos necesarios para que el nodo anuncie la nueva transaccion creada por el wallet.
pub struct TxToSend {
    size: usize,
    tx: Transaction,
}

impl TxToSend {
    /// Traduccion del struct a bytes.
    #[must_use]
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend(make_compact(self.size));
        buf.extend_from_slice(&self.tx.as_bytes());
        buf
    }

    /// Creacion del payload en base a una transaccion.
    /// # Errors:
    /// * `ErrorWhileParsing` si no se puede convertir el tamanio de la transaccion de usize a u32
    #[must_use]
    pub fn new(tx: Transaction) -> Self {
        Self {
            size: tx.as_bytes().len(),
            tx,
        }
    }

    /// Parseo del payload desde una variable que implementa el trait read
    /// `# Errors` :
    /// * `IncompleteMessage` si falla una de las lectura del stream
    pub fn from_reader(stream: &mut dyn Read) -> Result<Self, MessageError> {
        let size = parse_compact(stream)?;
        let tx = Transaction::parse_transaction(stream)?;
        Ok(Self { size, tx })
    }
}

pub struct POIRequest {
    pub txid: [u8; 32],
    pub height: u32,
}
impl POIRequest {
    /// Traduccion del struct a bytes.
    #[must_use]
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.txid);
        buf.extend_from_slice(&self.height.to_le_bytes());
        buf
    }

    /// Creacion del payload en base a el id de una transaccion y el height de un bloque.
    #[must_use]
    pub fn new(txid: [u8; 32], height: u32) -> Self {
        Self { txid, height }
    }

    /// Parseo del payload desde una variable que implementa el trait read
    /// `# Errors` :
    /// * `IncompleteMessage` si falla una de las lectura del stream
    pub fn from_reader(stream: &mut dyn Read) -> Result<Self, MessageError> {
        let mut buf_txid: [u8; 32] = [0; 32];
        stream.read_exact(&mut buf_txid)?;
        let mut height_buf: [u8; 4] = [0; 4];
        stream.read_exact(&mut height_buf)?;
        let height = <u32>::from_le_bytes(height_buf);
        Ok(Self {
            txid: buf_txid,
            height,
        })
    }
}
pub struct POIAnswer {
    pub txid: [u8; 32],
    pub count: usize,
    pub path: Vec<([u8; 32], [u8; 32])>,
}
impl POIAnswer {
    /// Traduccion del struct a bytes.
    #[must_use]
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&0_u8.to_le_bytes());
        buf.extend_from_slice(&self.txid);
        buf.extend_from_slice(&make_compact(self.count));
        for i in 0..self.count {
            buf.extend_from_slice(&self.path[i].0);
            buf.extend_from_slice(&self.path[i].1);
        }

        buf
    }

    /// Creacion del payload en base a un vector de paths.
    #[must_use]
    pub fn new(txid: [u8; 32], path: Vec<([u8; 32], [u8; 32])>) -> Self {
        Self {
            txid,
            count: path.len(),
            path,
        }
    }

    /// Parseo del payload desde una variable que implementa el trait read
    /// `# Errors`:
    /// * `IncompleteMessage` si falla una de las lectura del stream
    /// *
    pub fn from_reader(stream: &mut dyn Read) -> Result<Self, MessageError> {
        let mut txid: [u8; 32] = [0; 32];
        stream.read_exact(&mut txid)?;
        let count = parse_compact(stream)?;
        let mut path: Vec<([u8; 32], [u8; 32])> = Vec::new();
        for _i in 0..count {
            let mut izq_buf: [u8; 32] = [0; 32];
            stream.read_exact(&mut izq_buf)?;
            let mut der_buf: [u8; 32] = [0; 32];
            stream.read_exact(&mut der_buf)?;
            path.push((izq_buf, der_buf));
        }

        Ok(Self { txid, count, path })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::io::{BufReader, Cursor};

    #[test]
    fn parsing_and_unparsing_wallet_id() {
        let wallet_id: [u8; 20] = [
            0x00, 0x20, 0x34, 0x25, 0x00, 0x20, 0x34, 0x25, 0x00, 0x20, 0x34, 0x25, 0x00, 0x20,
            0x34, 0x25, 0x00, 0x20, 0x34, 0x25,
        ];
        let payload = WalletId::new(wallet_id);
        let payload_bytes = payload.as_bytes();
        let mut cursor = Cursor::new(payload_bytes);
        let payload_outcome = WalletId::from_reader(&mut cursor).unwrap();
        assert_eq!(payload_outcome, payload);
    }

    #[test]
    fn parsing_and_unparsing_incoming_tx() {
        let hash = "4ee3102ac6e2822babcedeb4f7f8b6b5a9cc508308e282575bed118c6d919a68";
        let hexa_hash_bytes = hex::decode(hash).expect("Failed to decode hex string");
        let txid: [u8; 32] = hexa_hash_bytes.try_into().unwrap();
        let tx_announce = IncomingTx::new(txid, 0, 10);
        let tx_announce_bytes = tx_announce.as_bytes();
        let mut reader = BufReader::new(tx_announce_bytes.as_slice());
        let unparsed = IncomingTx::from_reader(&mut reader).unwrap();
        assert_eq!(unparsed, tx_announce);
    }
    #[test]
    fn parsing_and_unparsing_utxo_response() {
        let hash = "4ee3102ac6e2822babcedeb4f7f8b6b5a9cc508308e282575bed118c6d919a68";
        let hexa_hash_bytes = hex::decode(hash).unwrap();
        let txid_1: [u8; 32] = hexa_hash_bytes.try_into().unwrap();
        let hash2 = "2ef398abc6ae2822babcedeb4f7f8b6b5a9cc508308e282575bed118c4d91bc2";
        let hexa_hash_bytes2 = hex::decode(hash2).unwrap();
        let txid_2: [u8; 32] = hexa_hash_bytes2.try_into().unwrap();
        let utxo_response = UtxoResponse::new(vec![
            UtxoInfo::new(233333, 10, txid_1, 1),
            UtxoInfo::new(284444, 13, txid_2, 2),
        ]);

        let response_bytes = utxo_response.as_bytes();
        let mut reader = BufReader::new(response_bytes.as_slice());
        let unparsed = UtxoResponse::from_reader(&mut reader).unwrap();
        assert_eq!(response_bytes, unparsed.as_bytes());
    }
}
