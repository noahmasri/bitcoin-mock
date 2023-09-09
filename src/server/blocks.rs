//! Este modulo contiene todas las estructuras y parseos necesarios para poder convertir un
//! arreglo de bytes en un bloque parseado tal como especifica el protocolo de desarrollo Bitcoin
use crate::server::merkletree::MerkleTree;
use crate::server::messages::MessageHeader;
use crate::utils::errors::DownloadError;
use crate::utils::tx::{Coinbase, Transaction};
use crate::{
    utils::compact_size::{make_compact, parse_compact},
    utils::errors::MessageError,
};
use bitcoin_hashes::{sha256d, Hash};
use chrono::{NaiveDate, NaiveDateTime, TimeZone, Utc};
use std::fs::File;
use std::io::{Read, Write};
use std::net::TcpStream;

const HEADER_SIZE: usize = 80;

#[derive(Copy, Clone, Debug)]
/// El header de un bloque. Contiene toda la informacion necesaria para identificarlo en la blockchain.
pub struct BlockHeader {
    /// indica la version de protocol que sigue
    pub version: i32,
    /// el hash del bloque anterior
    pub prev_blockhash: [u8; 32],
    /// el merkle root del merkle tree que se forma con todas las transacciones pertenencientes al bloque
    pub merkle_root: [u8; 32],
    /// indicador del tiempo de creacion del bloque
    pub timestamp: u32,
    /// la dificultad del objetivo
    pub bits: u32,
    /// un numero aleatorio
    pub nonce: u32,
    /// todos los campos del blockheader pasados a bytes, util para identificar rapidamente un bloque
    pub bytes: [u8; HEADER_SIZE],
}

impl BlockHeader {
    /// Devuelve un BlockHeader creado apartir de una referencia a un array con la cantidad
    /// de bytes necesarios para el header.
    /// # Errors
    /// * si no puede convertir los bytes en el tipo de dato pedido, devuelve MessageError::ErrorWhileParsing
    pub fn new(buf: &[u8; HEADER_SIZE]) -> Result<BlockHeader, MessageError> {
        let version = i32::from_le_bytes(buf[0..4].try_into()?);
        let prev_blockhash: [u8; 32] = buf[4..36].try_into()?;
        let merkle_root: [u8; 32] = buf[36..68].try_into()?;
        let timestamp = <u32>::from_le_bytes(buf[68..72].try_into()?);
        let bits = <u32>::from_le_bytes(buf[72..76].try_into()?);
        let nonce = <u32>::from_le_bytes(buf[76..80].try_into()?);
        let bytes = buf.to_owned();
        Ok(BlockHeader {
            version,
            prev_blockhash,
            merkle_root,
            timestamp,
            bits,
            nonce,
            bytes,
        })
    }
    /// Devuelve un BlockHeader creado leyendo de un stream
    /// # Errors
    /// * al intentar leer del stream, no se encuentra la cantidad de bytes pedida. El error obtenido
    /// es un DownloadError::EofEncountered
    pub fn parse_alleged_headers_message(
        stream: &mut TcpStream,
        file: &mut File,
    ) -> Result<Vec<BlockHeader>, DownloadError> {
        receive_message(stream, "headers\0\0\0\0\0")?;
        let headers = match Self::parse_block_headers(stream, Some(file)) {
            Ok(h) => h,
            Err(_) => Vec::new(),
        };
        Ok(headers)
    }

    fn get_header_from_reader(
        stream: &mut dyn Read,
    ) -> Result<([u8; HEADER_SIZE], [u8; 1]), DownloadError> {
        let mut buf_header: [u8; HEADER_SIZE] = [0; HEADER_SIZE];
        let mut buf_verif: [u8; 1] = [0; 1];
        stream.read_exact(&mut buf_header)?;
        stream.read_exact(&mut buf_verif)?;
        if buf_verif[0] != 0 {
            return Err(DownloadError::MessageNotRequested);
        }
        Ok((buf_header, buf_verif))
    }

    /// Devuelve un Vector de BlockHeaders creado leidos de un archivo una vez que termina de leerlo
    /// # Errors
    /// * al intentar leer del archivo, si el path es invalido devuelve MessageError::InvalidPath,
    /// * al intentar leer del archivo, si no se tienen los permisos necesarios devuelve MessageError::FilePermissionDenied,
    /// * al intentar leer del archivo, si el archivo no se puede leer ya que esta corrupto devuelve MessageError::CorruptFile,
    pub fn get_headers_from_file(file: &mut File) -> Result<Vec<BlockHeader>, DownloadError> {
        let mut headers: Vec<BlockHeader> = Vec::new();
        let mut keep_searching: bool = true;
        while keep_searching {
            match Self::get_header_from_reader(file) {
                Ok(h) => {
                    if let Ok(head) = Self::new(&h.0) {
                        headers.push(head);
                    }
                }
                Err(DownloadError::EofEncountered) => {
                    keep_searching = false;
                }
                Err(e) => return Err(e),
            }
        }
        Ok(headers)
    }

    fn parse_block_headers(
        stream: &mut dyn Read,
        file: Option<&mut File>,
    ) -> Result<Vec<BlockHeader>, DownloadError> {
        let mut headers = Vec::new();
        let header_count = parse_compact(stream)?;
        let mut i = 0;
        while i < header_count {
            let header = Self::get_header_from_reader(stream)?;
            if let Ok(head) = Self::new(&header.0) {
                if let Some(&mut ref mut f) = file {
                    f.write_all(&header.0)?;
                    f.write_all(&header.1)?;
                };
                headers.push(head);
            }
            i += 1;
        }
        Ok(headers)
    }

    /// Devuelve el doble Sha256 de un BlockHeaders
    pub fn hash(&self) -> [u8; 32] {
        sha256d::Hash::hash(&self.bytes).to_byte_array()
    }

    /// Devuelve el indice del primer BlockHeader encontrado a partir de una fecha dada
    pub fn find_index_first_block_header_since_date(
        block_headers: &Vec<BlockHeader>,
        date: NaiveDate,
    ) -> Option<usize> {
        let hora = chrono::NaiveTime::from_hms_opt(0, 0, 0)?;
        let fecha_datetime = NaiveDateTime::new(date, hora);
        let fecha_utc = Utc.from_utc_datetime(&fecha_datetime);
        let unix_date = fecha_utc.timestamp();

        (0..block_headers.len()).find(|&i| unix_date <= block_headers[i].timestamp as i64)
    }
}

/// Estructura de un Bloque en base al protocolo bitcoin
#[derive(Clone, Debug)]
pub struct Block {
    /// Header con la informacion principal sobre el nodo
    pub header: BlockHeader,
    /// Cantidad de transacciones, contando la coinbase
    pub txs_count: usize,
    /// Transaccion Coinbase, o primera transaccion del bloque
    pub coinbase_tx: Coinbase,
    /// Vector de transacciones, excluyendo la coinbase
    pub txs: Vec<Transaction>,
    /// Merkle Tree del bloque
    pub merkletree: MerkleTree,
}

impl Block {
    /// Convierte el struct Block en su formato en bytes, segun el protocolo bitcoin.
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut buf_message: Vec<u8> = Vec::new();
        buf_message.extend(self.header.bytes);
        buf_message.extend(make_compact(self.txs_count));
        buf_message.extend(self.coinbase_tx.as_bytes());
        for tx in self.txs.iter() {
            buf_message.extend(tx.as_bytes());
        }
        buf_message
    }

    /// Devuelve un Block creado leyendo de un stream.
    /// # Errors
    /// * al intentar leer del stream, no se encuentra la cantidad de bytes pedida. El error obtenido
    /// es un DownloadError::EofEncountered
    pub fn parse_alleged_blocks_message(stream: &mut TcpStream) -> Result<Block, DownloadError> {
        receive_message(stream, "block\0\0\0\0\0\0\0")?;
        let block = Self::parse_blocks_message(stream)?;
        Ok(block)
    }

    fn verify_merkle_root(
        txs: &[Transaction],
        coinbase: &Coinbase,
        merkle_root: [u8; 32],
    ) -> Result<MerkleTree, MessageError> {
        let mut txs_ids = vec![];
        txs_ids.push(coinbase.hash());
        for tx in txs.iter() {
            txs_ids.push(tx.hash());
        }

        let merkletree = MerkleTree::from_txs(&txs_ids)?;

        if !merkletree.verify_merkle_root(merkle_root) {
            return Err(MessageError::InvalidBlock);
        }
        Ok(merkletree)
    }

    /// Recibe un stream por el que se le envia el bloque.
    /// Lo parsea y devuelve el struct Block.
    ///
    /// # Errors
    /// * si no puede convertir los bytes en el tipo de dato pedido, devuelve MessageError::ErrorWhileParsing
    /// * al intentar leer del stream, no se encuentra la cantidad de bytes pedida. El error obtenido
    /// es un MessageError::IncompleteMessage
    /// * si el bloque no contiene transacciones. El error obtenido es MessageError::MissingCoinbaseTx
    pub fn parse_blocks_message(stream: &mut dyn Read) -> Result<Block, MessageError> {
        let mut buf_header: [u8; HEADER_SIZE] = [0; HEADER_SIZE];
        stream.read_exact(&mut buf_header)?;
        let header = BlockHeader::new(&buf_header)?;
        let txs_count = parse_compact(stream)?;
        let coinbase_tx = Coinbase::parse_coinbase_transaction(stream)?;
        let mut txs: Vec<Transaction> = Vec::new();
        for _ in 1..txs_count {
            let tx = Transaction::parse_transaction(stream)?;
            txs.push(tx);
        }
        let merkletree = match Self::verify_merkle_root(&txs, &coinbase_tx, header.merkle_root) {
            Ok(m) => m,
            Err(_e) => {
                return Err(MessageError::InvalidBlock);
            }
        };

        let block = Block {
            header,
            txs_count,
            coinbase_tx,
            txs,
            merkletree,
        };
        if !block.verify_proof_of_work()? {
            return Err(MessageError::InvalidBlock);
        }
        Ok(block)
    }

    /// Verifica la proof of work del bloque segun el criterio especificado en BitcoinDeveloper.
    /// Devuelve true si el hash del header es menor o igual al valor encodeado del campo nbits
    /// del mismo header. Devuelve false en caso contrario.
    ///
    /// # Errors
    /// * si no puede convertir los bytes en el tipo de dato pedido, devuelve MessageError::ErrorWhileParsing
    pub fn verify_proof_of_work(&self) -> Result<bool, MessageError> {
        let nbits_in_bytes = self.header.bits.to_be_bytes();
        let exponent = <u8>::from_be_bytes(nbits_in_bytes[0..1].try_into()?);
        let mut result = vec![0x00; exponent as usize];
        let mantissa = &nbits_in_bytes[1..];

        for i in 0..result.len() {
            if i < mantissa.len() {
                result[i] = mantissa[i];
            } else {
                break;
            }
        }

        let mut target = vec![0; (32 - exponent) as usize];
        if !result.is_empty() && ((result[0] >> 7) & 1) == 0 {
            target.extend_from_slice(&result);
        } else {
            target = vec![0; 32];
        }

        let header_hash: &[u8] = &self.header.hash();

        for i in 0..target.len() {
            if header_hash[header_hash.len() - 1 - i] != target[i] {
                return Ok(header_hash[header_hash.len() - 1 - i] <= target[i]);
            }
        }
        Ok(true) // son iguales
    }

    pub fn height(&self) -> u32 {
        self.coinbase_tx.tx_in.height
    }
}

/// Lee del stream recibido hasta que el mensaje sea el pasado por parametro.
///
/// # Errors
/// * Se cerro el stream o hay algun otro tipo de error de lectura
pub fn receive_message(stream: &mut TcpStream, command_name: &str) -> Result<(), MessageError> {
    let mut received = false;

    while !received {
        let header = MessageHeader::from_bytes(stream)?;
        let message_command_name = header.is_message();
        if message_command_name != command_name {
            header.ignore_payload(stream)?;
        } else {
            received = true;
        }
    }
    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn test_pow() {
        // Se uso el bloque 2436820 , link : https://blockstream.info/testnet/block/0000000000000006c1a712c30d3f9f52358cdcfd9b07b8258edb9566a9dcd055

        let block =
            Block::parse_blocks_message(&mut File::open("tests/some_blocks/block5").unwrap())
                .unwrap();
        assert!(block.verify_proof_of_work().unwrap());
    }
}
