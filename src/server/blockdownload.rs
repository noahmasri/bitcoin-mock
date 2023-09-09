//! Este modulo contiene lo necesario para realizar la descarga los headers y bloques.
use crate::server::blockgetter::Blockgetter;
use crate::server::blocks::{Block, BlockHeader};
use crate::server::logfile::write_in_log;
use crate::server::messages::{GetDataMessage, GetHeadersMessage, Message};
use crate::server::utxos::{get_utxo_set, update_hash_with_block, UtxoInfo};
use crate::utils::errors::{DownloadError, MessageError};
use chrono::NaiveDate;
use rand::distributions::Alphanumeric;
use rand::Rng;
use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::net::TcpStream;
use std::path::Path;
use std::sync::mpsc::Sender;

const MAX_HEADERS: usize = 2000;
pub const GENESIS_BLOCK_HASH: [u8; 32] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x19, 0xd6, 0x68, 0x9c, 0x08, 0x5a, 0xe1, 0x65, 0x83, 0x1e, 0x93,
    0x4f, 0xf7, 0x63, 0xae, 0x46, 0xa2, 0xa6, 0xc1, 0x72, 0xb3, 0xf1, 0xb6, 0x0a, 0x8c, 0xe2, 0x6f,
];

/// Estructura donde guardamos datos sobre la blockchain
pub struct Blockchain {
    /// Lista de headers descargados en inicial headers download, ordenados temporalmente
    pub block_headers: Headers,
    /// Index del primer bloque que descargamos
    pub first_block_index: usize,
    /// Lista de bloques descargados, ordenados temporalmente
    pub blocks: HashMap<[u8; 32], Block>,
    /// HashMap de los utxo, mapeados por el hash de la clave publica de los outputs
    pub utxo_set: HashMap<[u8; 20], Vec<UtxoInfo>>,
}

pub struct Headers {
    pub map: HashMap<[u8; 32], usize>,
    pub list: Vec<BlockHeader>,
}

impl Blockchain {
    fn default() -> Self {
        Blockchain {
            block_headers: Headers {
                map: HashMap::new(),
                list: Vec::new(),
            },
            first_block_index: 0,
            blocks: HashMap::new(),
            utxo_set: HashMap::new(),
        }
    }

    fn get_missing_headers(
        first_hash_to_send: [u8; 32],
        node: &mut TcpStream,
        headers_file: &mut File,
        headers: &mut Vec<BlockHeader>,
        headers_map: &mut HashMap<[u8; 32], usize>,
    ) -> Result<(), DownloadError> {
        let mut hash_to_send = first_hash_to_send;
        let mut relay_node_has_headers_to_send = true;
        while relay_node_has_headers_to_send {
            let my_get_headers = GetHeadersMessage::new(70015, hash_to_send);
            my_get_headers.send_message(node)?;

            let just_read = match BlockHeader::parse_alleged_headers_message(node, headers_file) {
                Ok(h) => h,
                Err(_) => break,
            };
            if just_read.len() != MAX_HEADERS {
                relay_node_has_headers_to_send = false;
            }

            for (i, header) in just_read.iter().enumerate() {
                headers_map.insert(header.hash(), i);
            }
            headers.extend(just_read.clone());
            hash_to_send = headers[headers.len() - 1].hash();
        }
        if headers.is_empty() {
            return Err(DownloadError::EofEncountered);
        }
        Ok(())
    }

    fn initial_headers_download(
        relay_node: &TcpStream,
        headers_file: &mut File,
    ) -> Result<Headers, DownloadError> {
        let mut node = relay_node.try_clone()?;
        let mut hash_to_send: [u8; 32] = GENESIS_BLOCK_HASH;
        let mut headers: Vec<BlockHeader> = Vec::new();
        let mut headers_map: HashMap<[u8; 32], usize> = HashMap::new();
        if let Ok(h) = BlockHeader::get_headers_from_file(headers_file) {
            for (i, header) in h.iter().enumerate() {
                headers_map.insert(header.hash(), i);
            }
            headers.extend(h);
            if let Some(last) = headers.last() {
                hash_to_send = last.hash();
            }
        };

        Blockchain::get_missing_headers(
            hash_to_send,
            &mut node,
            headers_file,
            &mut headers,
            &mut headers_map,
        )?;

        Ok(Headers {
            map: headers_map,
            list: headers,
        })
    }

    fn handle_headers_and_log(
        relay_node: &TcpStream,
        file: &mut File,
        log_file: Option<Sender<String>>,
    ) -> Result<Headers, DownloadError> {
        match Self::initial_headers_download(relay_node, file) {
            Ok(header) => {
                write_in_log(
                    vec![format!(
                        "Finished headers download, having downloaded {}",
                        header.list.len()
                    )],
                    log_file,
                );
                Ok(header)
            }
            Err(e) => {
                write_in_log(
                    vec![format!("Error: {:?}, couldn't finish headers download", e)],
                    log_file,
                );
                Err(e)
            }
        }
    }

    fn find_blocks_to_download(
        start_date: NaiveDate,
        blockchain: &mut Blockchain,
    ) -> HashSet<[u8; 32]> {
        let mut blocks_to_find = HashSet::new();
        if let Some(index_to_fetch) = BlockHeader::find_index_first_block_header_since_date(
            &blockchain.block_headers.list,
            start_date,
        ) {
            blockchain.first_block_index = index_to_fetch;

            for block_header in blockchain.block_headers.list.iter().skip(index_to_fetch) {
                blocks_to_find.insert(block_header.hash()); // returns hashes of all headers to download
            }
        }
        blocks_to_find
    }

    /// Crea un get data message con los datos del blockheader recibido y lo envia al relay node.
    /// Espera a un message block.
    /// Si lo recibe lo parsea y lo devuelve
    /// # Errors
    /// * si no recibe como respuesta un block message devuelve "`DownloadError::InvalidBlock`"
    /// * si hay un unexpected eof al leer o escribir del stream devuelve "`DownloadError::ErrorWhileParsing`""
    pub fn download_block(
        relay_node: TcpStream,
        block_to_download: [u8; 32],
    ) -> Result<Block, DownloadError> {
        let mut node = relay_node.try_clone()?;
        let my_get_data = GetDataMessage::new(vec![(2, block_to_download)]);
        my_get_data.send_message(&mut node)?;
        let block = Block::parse_alleged_blocks_message(&mut node)?;
        Ok(block)
    }

    fn download_blocks_with_threads(
        streams: &Vec<TcpStream>,
        blocks_to_find: HashSet<[u8; 32]>,
    ) -> Result<HashMap<[u8; 32], Block>, DownloadError> {
        let mut pool = Blockgetter::new(streams, blocks_to_find)?;
        let blocks = pool.receive_blocks()?;
        Ok(blocks)
    }

    fn generate_random_key(length: usize) -> String {
        let rng = rand::thread_rng();
        let key: String = rng
            .sample_iter(&Alphanumeric)
            .take(length)
            .map(char::from)
            .collect();
        key
    }

    fn persist_new_blocks(
        dir_path: &str,
        blocks: &HashMap<[u8; 32], Block>,
    ) -> Result<(), DownloadError> {
        if fs::metadata(dir_path).is_err() {
            fs::create_dir(dir_path)?;
        }
        let mut file_name = format!("{}/{}", dir_path, Self::generate_random_key(15));
        let mut cur_file = OpenOptions::new()
            .append(true)
            .create(true)
            .open(&file_name)?;

        for (i, block) in blocks.values().enumerate() {
            if (i + 1) % 1000 == 0 {
                cur_file.flush()?;
                drop(cur_file);
                file_name = format!("{}/{}", dir_path, Self::generate_random_key(15));
                cur_file = OpenOptions::new()
                    .append(true)
                    .create(true)
                    .open(&file_name)?;
            }
            cur_file.write_all(&block.as_bytes())?;
        }

        Ok(())
    }

    fn handle_blocks_and_log(
        log_file: Option<Sender<String>>,
        nodes: &Vec<TcpStream>,
        block_dir_path: &str,
        blocks_to_find: HashSet<[u8; 32]>,
    ) -> Result<HashMap<[u8; 32], Block>, DownloadError> {
        let amount_to_find = blocks_to_find.len();
        let mut tasks = blocks_to_find;
        let persisted_blocks = Blockchain::get_blocks_from_path(block_dir_path, &mut tasks)?;
        let mut blocks = match Self::download_blocks_with_threads(nodes, tasks) {
            Ok(b) => b,
            Err(e) => {
                write_in_log(
                    vec![format!("Error: {:?}, couldn't finish blocks download", e)],
                    log_file,
                );
                return Err(e);
            }
        };
        if let Err(e) = Blockchain::persist_new_blocks(block_dir_path, &blocks) {
            write_in_log(
                vec![format!("Error: {:?}, couldn't persist new blocks", e)],
                log_file.clone(),
            );
        }

        blocks.extend(persisted_blocks.into_iter());
        if amount_to_find != blocks.len() {
            write_in_log(vec![format!("Error, couldn't fetch all blocks")], log_file);
            return Err(DownloadError::EofEncountered);
        }

        write_in_log(
            vec![format!(
                "Finished block download, having downloaded {} blocks",
                blocks.len()
            )],
            log_file,
        );

        Ok(blocks)
    }

    /// Descarga bloques desde una fecha, pidiendoselos a los nodos pasados por parametro. Recibe un archivo
    /// de persistencia de headers, para evitar descargarlos de cero.
    /// Devuelve un blockchain
    /// # Errors
    /// * Si no se puede clonar un stream devolvera `DownloadError:CloneFailed`,
    /// * Puede fallar por la lectura del archivo y devolver: `DownloadError::InvalidPath,DownloadError::FilePermissionDenied`,
    /// o  `DownloadError::CorruptFile`
    /// * Puede fallar por el envio de mensajes por un channel con `DownloadError::ConnectionFailed`
    pub fn initial_block_download(
        nodes: &Vec<TcpStream>,
        start_date: NaiveDate,
        header_file_path: &str,
        block_dir_path: &str,
        log_file: Option<Sender<String>>,
    ) -> Result<Blockchain, DownloadError> {
        let mut blockchain = Blockchain::default();
        let relay_node = nodes[0].try_clone()?;
        let mut file = OpenOptions::new()
            .append(true)
            .create(true)
            .read(true)
            .open(header_file_path)?;
        let headers = Blockchain::handle_headers_and_log(&relay_node, &mut file, log_file.clone())?;
        blockchain.block_headers = headers;
        let blocks_to_find = Self::find_blocks_to_download(start_date, &mut blockchain);

        blockchain.blocks =
            Blockchain::handle_blocks_and_log(log_file, nodes, block_dir_path, blocks_to_find)?;

        get_utxo_set(&mut blockchain);

        Ok(blockchain)
    }

    fn update_utxos_with_moved_blocks(&mut self, index_moved: usize) {
        for header in self.block_headers.list[index_moved..].iter() {
            if let Some(block) = self.blocks.get(&header.hash()) {
                update_hash_with_block(block, &mut self.utxo_set);
            }
        }
    }

    fn search_new_block_index(&mut self, block: Block) -> bool {
        for (i, b) in self.block_headers.list.iter().enumerate().rev() {
            if block.header.hash() == b.hash() {
                break;
            }
            if let Some(curr) = self.blocks.get(&b.hash()) {
                if block.height() > curr.height() {
                    self.block_headers
                        .list
                        .insert(self.first_block_index + i + 1, block.header);

                    // actualizar la posicion d todos los posteriores
                    for (j, head) in self.block_headers.list[self.first_block_index + i + 1..]
                        .iter()
                        .enumerate()
                    {
                        self.block_headers
                            .map
                            .insert(head.hash(), self.first_block_index + i + 1 + j);
                    }

                    self.blocks.insert(block.header.hash(), block);
                    self.update_utxos_with_moved_blocks(self.first_block_index + i + 1);
                    return false;
                }
            }
        }
        true
    }

    ///Devuelve verdadero si el bloque ya estaba incluido en la blockchain
    ///returns false and includes it if it wasnt
    pub fn is_block_included(&mut self, block: Block) -> bool {
        //should not download this block
        if let Some(first_block) = self
            .blocks
            .get(&self.block_headers.list[self.first_block_index].hash())
        {
            if block.height() < first_block.height() {
                return true;
            }
        }

        //block was already included
        if self.blocks.get(&block.header.hash()).is_some() {
            return true;
        }

        //block is newer than last registered block
        if let Some(last_block) = self
            .blocks
            .get(&self.block_headers.list[self.block_headers.list.len() - 1].hash())
        {
            if last_block.height() < block.height() {
                self.block_headers
                    .map
                    .insert(block.header.hash(), self.block_headers.list.len());
                self.block_headers.list.push(block.header);
                update_hash_with_block(&block, &mut self.utxo_set);
                self.blocks.insert(block.header.hash(), block);
                return false;
            }
        }

        //block is already there or should be in the middle
        self.search_new_block_index(block)
    }

    fn get_blocks_from_path(
        path: &str,
        to_find: &mut HashSet<[u8; 32]>,
    ) -> Result<HashMap<[u8; 32], Block>, DownloadError> {
        let mut blocks: HashMap<[u8; 32], Block> = HashMap::new();
        let dir = Path::new(path);
        if dir.is_dir() {
            for entry in fs::read_dir(dir)? {
                let entry = entry?;
                let entry_path = entry.path();
                if entry_path.is_dir() {
                    continue;
                }
                let mut file = fs::File::open(&entry_path)?;
                loop {
                    match Block::parse_blocks_message(&mut file) {
                        Ok(block) => {
                            if to_find.contains(&block.header.hash()) {
                                to_find.remove(&block.header.hash());
                                blocks.insert(block.header.hash(), block);
                            }
                        }
                        Err(MessageError::IncompleteMessage) => break,
                        Err(_) => return Err(DownloadError::CorruptFile),
                    };
                }
            }
        }
        Ok(blocks)
    }
}

#[cfg(test)]
mod test {

    use bitcoin_hashes::{sha256d, Hash};
    use chrono::NaiveDate;

    use super::*;
    use std::{collections::HashMap, fs::File, str::FromStr};

    fn create_headers_with_timestamp(timestamp: u32) -> BlockHeader {
        let prev_blockhash: [u8; 32] = [
            0x7F, 0x11, 0x01, 0x00, 0x0F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF8, 0x50,
            0x4E, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF0, 0xCA, 0xB4, 0xF3, 0xA7, 0x0C, 0x00, 0x00,
            0x01, 0x00, 0x00, 0x00,
        ];
        let merkleroot: [u8; 32] = [
            0x7F, 0x11, 0x01, 0x00, 0x0F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF8, 0x50,
            0x4E, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF0, 0xCA, 0xB4, 0xF3, 0xA7, 0x0C, 0x00, 0x00,
            0x01, 0x00, 0x00, 0x00,
        ];
        BlockHeader {
            version: 70015,
            prev_blockhash,
            merkle_root: merkleroot,
            timestamp, //13-5-2021
            bits: 10000000,
            nonce: 1299203900,
            bytes: [0; 80],
        }
    }
    #[test]
    fn can_find_point_in_blockchain() {
        let header1 = create_headers_with_timestamp(1620921600); //13-5-2021
        let header2 = create_headers_with_timestamp(1630444800); //1-9-2021
        let header3 = create_headers_with_timestamp(1640995200); //1-1-2022
        let header4 = create_headers_with_timestamp(1672531200); //1-1-2023
        let mut block_headers: Vec<BlockHeader> = Vec::new();
        block_headers.push(header1);
        block_headers.push(header2);
        block_headers.push(header3);
        block_headers.push(header4);

        if let Some(start_date) = NaiveDate::from_ymd_opt(2022, 3, 2) {
            if let Some(index) =
                BlockHeader::find_index_first_block_header_since_date(&block_headers, start_date)
            {
                assert_eq!(3, index);
            } else {
                assert_eq!(2, 0);
            }
        }
    }

    #[test]
    fn blocks_gotten_are_ordered_by_timestamp() -> Result<(), DownloadError> {
        let blocks: Vec<Block> = vec![
            Block::parse_blocks_message(&mut File::open("tests/some_blocks/block1")?)?,
            Block::parse_blocks_message(&mut File::open("tests/some_blocks/block2")?)?,
            Block::parse_blocks_message(&mut File::open("tests/some_blocks/block3")?)?,
            Block::parse_blocks_message(&mut File::open("tests/some_blocks/block4")?)?,
            Block::parse_blocks_message(&mut File::open("tests/some_blocks/block5")?)?,
        ];

        for i in 0..blocks.len() - 1 {
            assert!(blocks[i].header.timestamp <= blocks[i + 1].header.timestamp);
        }

        Ok(())
    }

    #[test]
    fn blocks_are_added_correctly_if_needed_to() {
        let first_block =
            Block::parse_blocks_message(&mut File::open("tests/some_blocks/block1").unwrap())
                .unwrap();
        let block2 =
            Block::parse_blocks_message(&mut File::open("tests/some_blocks/block3").unwrap())
                .unwrap();
        let last_block =
            Block::parse_blocks_message(&mut File::open("tests/some_blocks/block5").unwrap())
                .unwrap();

        let mut blocks: HashMap<[u8; 32], Block> = HashMap::new();
        blocks.insert(first_block.header.hash(), first_block.clone());
        blocks.insert(block2.header.hash(), block2.clone());
        blocks.insert(last_block.header.hash(), last_block.clone());

        let headers = vec![first_block.header, block2.header, last_block.header];
        let mut map = HashMap::new();
        for (i, h) in headers.iter().enumerate() {
            map.insert(h.hash(), i);
        }
        let mut blockchain = Blockchain {
            block_headers: Headers { map, list: headers },
            first_block_index: 0,
            blocks,
            utxo_set: HashMap::new(),
        };
        let same_block1 =
            Block::parse_blocks_message(&mut File::open("tests/some_blocks/block1").unwrap())
                .unwrap();
        blockchain.is_block_included(same_block1);
        assert_eq!(blockchain.blocks.len(), 3);
        assert_eq!(blockchain.block_headers.list.len(), 3);
        let block2 =
            Block::parse_blocks_message(&mut File::open("tests/some_blocks/block2").unwrap())
                .unwrap();
        blockchain.is_block_included(block2);
        assert_eq!(blockchain.blocks.len(), 4);
        assert_eq!(blockchain.block_headers.list.len(), 4);

        let block4 =
            Block::parse_blocks_message(&mut File::open("tests/some_blocks/block4").unwrap())
                .unwrap();
        blockchain.is_block_included(block4);
        assert_eq!(blockchain.blocks.len(), 5);
        assert_eq!(blockchain.block_headers.list.len(), 5);

        let mut prev_height = 0;
        for (i, head) in blockchain.block_headers.list.iter().enumerate() {
            if let Some(curr) = blockchain.blocks.get(&head.hash()) {
                assert!(prev_height <= curr.height());
                prev_height = curr.height();
            }
            if let Some(header_index) = blockchain.block_headers.map.get(&head.hash()) {
                assert_eq!(*header_index, i);
            }
        }
    }

    #[test]
    fn blocks_are_uploaded_from_files() {
        let mut wanted = HashSet::new();
        let blocks =
            Blockchain::get_blocks_from_path("tests/some_blocks", &mut HashSet::new()).unwrap();
        assert_eq!(blocks.len(), 0);

        let hash1_str = "0000000000002500eda5aea2f9ae6b9739032f68b84530625a491ca4d8e725ec";
        let hash1 = sha256d::Hash::from_str(hash1_str).unwrap();
        let hash2_str = "00000000000000112113ee7d711c9794728f7e8f66e5d60282af2b07496fea29";
        let hash2 = sha256d::Hash::from_str(hash2_str).unwrap();
        let hash3_str = "000000000000791cb9a9a662993721ad0c19ba6e5873ea10724977e6c384b8bb";
        let hash3 = sha256d::Hash::from_str(hash3_str).unwrap();
        let hash4_str = "0000000000006eb71b0d7d5b3789e8e2d88960e204e73c67e1e1067666c03a0b";
        let hash4 = sha256d::Hash::from_str(hash4_str).unwrap();
        let hash5_str = "0000000000000006c1a712c30d3f9f52358cdcfd9b07b8258edb9566a9dcd055";
        let hash5 = sha256d::Hash::from_str(hash5_str).unwrap();

        wanted.insert(hash1.to_byte_array());
        wanted.insert(hash2.to_byte_array());
        wanted.insert(hash3.to_byte_array());
        wanted.insert(hash4.to_byte_array());
        wanted.insert(hash5.to_byte_array());

        let same_blocks =
            Blockchain::get_blocks_from_path("tests/some_blocks", &mut wanted).unwrap();
        assert_eq!(same_blocks.len(), 5);
        assert!(wanted.is_empty());
    }
}
