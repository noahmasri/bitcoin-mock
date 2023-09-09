//! Este modulo contiene todas las funciones del nodo como servidor
//! y dentro de la red peer to peer de bitcoin. Puede manejar los
//! pedidos de los clientes, como tambien agregar nuevos bloques a su
//! cadena.

use std::cmp::Ordering;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, TcpListener, TcpStream};
use std::sync::{mpsc, Arc, Mutex};

use crate::server::blockdownload::Blockchain;
use crate::server::blocks::Block;
use crate::server::handshake::{get_ips_address, handshakes};
use crate::server::logfile::write_in_log;
use crate::server::networklistener::NetworkListener;
use crate::server::utxos::{get_pkhash_from_pkscript, get_pkhash_from_sigscript};
use crate::utils::config::{Config, Peers};
use crate::utils::errors::NodeError;
use crate::utils::tx::Transaction;
use crate::utils::wallet_messages::{
    BlockInclusion, IncomingTx, POIAnswer, POIRequest, Payload, UtxoResponse, WalletId,
    WalletMessage, WalletMessageHeader,
};

use super::handshake::wait_for_handshake;
use super::messages::TESTNET_PORT;

/// Estructura de nodo bitcoin
pub struct Node {
    /// Su copia personal de la blockchain
    pub blockchain: Blockchain,
    /// Las cuentas con las que se vinculo. La clave es el hash de la clave publica de la wallet,
    /// y el valor el Stream mediante el cual se comunica con ella
    pub accounts: HashMap<[u8; 20], TcpStream>,
    /// Las transacciones que esta encargado de broadcastear. La clave es el hash de la transaccion,
    /// el valor es una tupla (Transaccion, Hash de la clave publica del creador)
    pub broadcasted_tx: HashMap<[u8; 32], (Transaction, [u8; 20])>,
    /// Nodos con los que esta conectado
    pub peers: Vec<TcpStream>,
    /// Direccion desde la que se conecta con los peers
    pub address: (IpAddr, u16),
}

impl Node {
    /// A partir de una estructura de configuracion, un puerto y un archivo en el que loggear,
    /// la funcion se conecta a todas las direcciones obtenidas de un dns resolver y comienza
    /// a pedir los bloques de la cadena.
    ///
    /// # Errors:
    /// * Si no logra obtener direcciones mediante el dns resolver, devuelve NodeError::CouldNotFetchAddrs
    /// * Si no puede realizar el handshake con ninguna de las direcciones obtenidas, devuelve NodeError::UnableToConnectToPeers
    /// * Si no puede realizar el inicial block download, devuelve NodeError::CouldNotDownloadBlocks
    pub fn new(
        config: Config,
        port: u16,
        sender_log: Option<mpsc::Sender<String>>,
    ) -> Result<Self, NodeError> {
        let nodes_addr: Vec<(IpAddr, u16)> = match config.peers {
            Peers::DOMAIN(d) => get_ips_address(d.as_str(), port)?,
            Peers::ADDRESS(addr) => addr,
        };

        let peers = handshakes(
            70015,
            (config.ip_address, port),
            0,
            nodes_addr,
            sender_log.clone(),
        )?;

        let blockchain = Blockchain::initial_block_download(
            &peers,
            config.start_date,
            config.headers_file.as_str(),
            config.blocks_dir.as_str(),
            sender_log,
        )?;

        Ok(Self {
            blockchain,
            accounts: HashMap::new(),
            broadcasted_tx: HashMap::new(),
            peers,
            address: (config.ip_address, port),
        })
    }

    fn connect_to_wallet(
        &self,
        stream: &mut dyn Read,
        sender_log: Option<mpsc::Sender<String>>,
    ) -> Result<[u8; 20], NodeError> {
        let header = WalletMessageHeader::from_reader(stream)?;
        let request = header.message_name();
        if request != "bindwallet\0\0" {
            return Err(NodeError::ExpectedHandshake);
        }

        let payload = WalletId::from_reader(stream)?;
        let pk_hash = hex::encode(payload.get_public_key_hash());
        write_in_log(
            vec![format!("Binded wallet with public key hash {}", pk_hash)],
            sender_log,
        );
        Ok(payload.get_public_key_hash())
    }

    /// La funcion genera un servidor mediante la conexion a una direccion pasada por parametro, y
    /// escucha por conexiones entrantes. Una vez realizada una conexion, si esta es exitosa, se agrega al
    /// cliente al hashmap del nodo y luego crea un nuevo thread para la comunicacion con este cliente particular
    /// donde escucha por sus pedidos y realiza las acciones pertinentes.
    pub fn listen_for_clients(
        node: Arc<Mutex<Self>>,
        address: (IpAddr, u16),
        net_listener: Arc<Mutex<NetworkListener>>,
        sender_log: Option<mpsc::Sender<String>>,
    ) -> Result<(), NodeError> {
        let listener = TcpListener::bind(address)?;
        let mut threads = Vec::new();
        for client_stream in listener.incoming() {
            let node_clone = node.clone();
            let mut locked_node = node_clone.lock()?;
            let mut stream_clone = client_stream?.try_clone()?;
            if let Ok(w) = locked_node.connect_to_wallet(&mut stream_clone, sender_log.clone()) {
                locked_node.accounts.insert(w, stream_clone.try_clone()?);
                drop(locked_node);
                let log = sender_log.clone();
                let net_listener_clone = net_listener.clone();
                let thread = std::thread::spawn(move || {
                    Self::handle_client(node_clone, &mut stream_clone, net_listener_clone, log)
                });

                threads.push(thread);
            }
        }

        for handle in threads {
            if handle.join().is_err() {
                return Err(NodeError::UnableToJoinHandles);
            }
        }

        Ok(())
    }

    fn handle_peer(
        peer_stream: TcpStream,
        my_address: (IpAddr, u16),
        node: Arc<Mutex<Node>>,
        net_listener: Arc<Mutex<NetworkListener>>,
        sender_log: Option<mpsc::Sender<String>>,
    ) -> Result<(), NodeError> {
        let mut stream_clone = peer_stream.try_clone()?;
        if wait_for_handshake(&mut stream_clone, my_address).is_ok() {
            let stream_cloned = stream_clone.try_clone()?;
            NetworkListener::add_new_peer(net_listener, stream_cloned, sender_log);
            let mut locked_node = node.lock()?;
            locked_node.peers.push(stream_clone);
            drop(locked_node);
        }
        Ok(())
    }

    pub fn listen_for_peers(
        node: Arc<Mutex<Node>>,
        sender_log: Option<mpsc::Sender<String>>,
        net_listener: Arc<Mutex<NetworkListener>>,
    ) -> Result<(), NodeError> {
        let my_address = (IpAddr::from(Ipv4Addr::LOCALHOST), TESTNET_PORT);
        let listener = TcpListener::bind(my_address)?;
        for peer_stream in listener.incoming().flatten() {
            if Node::handle_peer(
                peer_stream,
                my_address,
                node.clone(),
                net_listener.clone(),
                sender_log.clone(),
            )
            .is_err()
            {
                continue;
            }
        }

        Ok(())
    }

    fn broadcast_tx(
        node: Arc<Mutex<Node>>,
        tx: Transaction,
        sender: [u8; 20],
        listener: Arc<Mutex<NetworkListener>>,
    ) -> Result<(), NodeError> {
        let mut locked_node = node.lock()?;
        let tx_hash = tx.hash();
        locked_node.broadcasted_tx.insert(tx_hash, (tx, sender));
        drop(locked_node);
        let locked_listener = listener.lock()?;
        locked_listener.broadcast_transaction(tx_hash);
        Ok(())
    }

    pub fn check_if_announcement_is_required(
        &self,
        block_height: u32,
        tx_hash: [u8; 32],
        tx_to_announce: &mut Vec<(BlockInclusion, [u8; 20])>,
        tx: &Transaction,
    ) {
        if let Some((_tx, sender_pk)) = self.broadcasted_tx.get(&tx_hash) {
            let inclusion = BlockInclusion::new(tx_hash, block_height);
            tx_to_announce.push((inclusion, *sender_pk));
        } else {
            for out in tx.tx_out.iter() {
                if let Ok(pk) = get_pkhash_from_pkscript(&out.pk_script) {
                    let sender = pk;
                    if self.accounts.get(&pk).is_some() {
                        let inclusion = BlockInclusion::new(tx_hash, block_height);
                        tx_to_announce.push((inclusion, sender));
                    }
                }
            }
        }
    }

    /// Recibe un vector de tuplas de mensajes de incoming tx y referencias a hash de una clave publica a quien se debe
    /// anunciar la nueva transaccion, y envia los mensajes mediante todos los streams que correspondan.
    /// Si no se puede enviar el mensaje entonces el nodo elimina su registro de coneccion con dicha wallet.
    pub fn announce_incoming_txs(&mut self, announcements: Vec<(IncomingTx, [u8; 20])>) {
        for (in_tx, pk_hash) in announcements {
            if let Some(mut stream) = self.accounts.get(&pk_hash) {
                let msg = WalletMessage::new(Payload::AnnounceTx(in_tx));
                if let Err(_e) = stream.write_all(&msg.as_bytes()) {
                    self.accounts.remove(&pk_hash);
                }
            }
        }
    }

    /// Recibe un vector de tuplas de mensajes de inclusion en bloques y referencias a hash de una clave publica a quien se debe
    /// anunciar la inclusion de una transaccion en el bloque, y envia todos los mensajes mediante el stream que corresponda.
    /// Si no se puede enviar el mensaje entonces el nodo elimina su registro de coneccion con dicha wallet.
    pub fn announce_inclusion_in_block(&mut self, announcements: Vec<(BlockInclusion, [u8; 20])>) {
        for (block_inc, pk_hash) in announcements {
            if let Some(mut stream) = self.accounts.get(&pk_hash) {
                self.broadcasted_tx.remove(&block_inc.txid());
                let msg = WalletMessage::new(Payload::AnnounceBlockInclusion(block_inc));
                if stream.write_all(&msg.as_bytes()).is_err() {
                    self.accounts.remove(&pk_hash);
                }
            }
        }
    }

    fn search_block_of_height(
        blockchain: &Blockchain,
        start: usize,
        end: usize,
        height: u32,
    ) -> Option<Block> {
        if let Some(start_block) = blockchain
            .blocks
            .get(&blockchain.block_headers.list[start].hash())
        {
            if let Some(end_block) = blockchain
                .blocks
                .get(&blockchain.block_headers.list[end].hash())
            {
                if start_block.height() > height || end_block.height() < height || start > end {
                    return None;
                }
            }
        }

        let mid: usize = (start + end) / 2;
        if let Some(mid_block) = blockchain
            .blocks
            .get(&blockchain.block_headers.list[mid].hash())
        {
            match mid_block.height().cmp(&height) {
                Ordering::Equal => return Some(mid_block.clone()),
                Ordering::Less => {
                    return Self::search_block_of_height(blockchain, mid + 1, end, height)
                }
                Ordering::Greater => {
                    return Self::search_block_of_height(blockchain, start, mid - 1, height)
                }
            }
        }
        None
    }

    /// Hace la proof of inclusion con el bloque y la transaccion pasada por parametro.
    pub fn make_proof_of_inclusion(
        &self,
        height: u32,
        txid: [u8; 32],
    ) -> Option<Vec<([u8; 32], [u8; 32])>> {
        if self.blockchain.blocks.is_empty() {
            return None;
        }
        if let Some(block) = Node::search_block_of_height(
            &self.blockchain,
            self.blockchain.first_block_index,
            self.blockchain.block_headers.list.len() - 1,
            height,
        ) {
            let proof = match block.merkletree.proof_of_inclusion(&txid) {
                Ok(proof) => proof,
                Err(_) => return Some(vec![]),
            };
            match proof.verify_proof() {
                true => return Some(proof.get_proof()),
                false => return Some(vec![]),
            };
        }
        None
    }

    fn get_response_for_utxos(&self, wallet: WalletId) -> WalletMessage {
        let pk_hash = wallet.get_public_key_hash();
        let mut utxo_response = UtxoResponse::new(vec![]);
        if let Some(utxos) = self.blockchain.utxo_set.get(&pk_hash) {
            utxo_response = UtxoResponse::new(utxos.clone());
        }
        WalletMessage::new(Payload::SendUtxo(utxo_response))
    }

    fn answer_poi_request(node: Arc<Mutex<Node>>, stream: &mut TcpStream) -> Result<(), NodeError> {
        if let Ok(request) = POIRequest::from_reader(stream) {
            if let Ok(locked_node) = node.lock() {
                let proof = locked_node.make_proof_of_inclusion(request.height, request.txid);
                drop(locked_node);
                match proof {
                    Some(path) => {
                        stream.write_all(
                            &WalletMessage::new(Payload::PoiAnswer(POIAnswer::new(
                                request.txid,
                                path,
                            )))
                            .as_bytes(),
                        )?;
                    }
                    None => {
                        stream.write_all(&WalletMessage::new(Payload::PoiError).as_bytes())?;
                    }
                }
            }
        }
        Ok(())
    }

    fn answer_utxo_request(
        node: Arc<Mutex<Node>>,
        stream: &mut TcpStream,
    ) -> Result<(), NodeError> {
        if let Ok(w) = WalletId::from_reader(stream) {
            if let Ok(locked_node) = node.lock() {
                stream.write_all(&locked_node.get_response_for_utxos(w).as_bytes())?;
            }
        }
        Ok(())
    }

    fn answer_tx_creation_request(
        node: Arc<Mutex<Node>>,
        stream: &mut TcpStream,
        network_listener: Arc<Mutex<NetworkListener>>,
        sender_log: Option<mpsc::Sender<String>>,
    ) -> Result<(), NodeError> {
        if let Ok(tx) = Transaction::parse_transaction(stream) {
            if let Ok(sender) = get_pkhash_from_sigscript(&tx.tx_in[0].signature_script) {
                let txid = tx.hash();
                Node::broadcast_tx(node, tx, sender, network_listener)?;
                let pk_readable = hex::encode(sender);
                let txid = hex::encode(txid);
                write_in_log(
                    vec![format!(
                        "{} created transaction with hash {}",
                        pk_readable, txid
                    )],
                    sender_log,
                );
            }
        }
        Ok(())
    }

    fn close_connection_to_wallet(node: Arc<Mutex<Node>>, stream: &mut TcpStream) {
        if let Ok(w) = WalletId::from_reader(stream) {
            if let Ok(mut locked_node) = node.lock() {
                locked_node.accounts.remove(&w.get_public_key_hash());
            }
        }
    }

    fn handle_client(
        node: Arc<Mutex<Node>>,
        stream: &mut TcpStream,
        network_listener: Arc<Mutex<NetworkListener>>,
        sender_log: Option<mpsc::Sender<String>>,
    ) -> Result<(), NodeError> {
        let mut buf = [0; 1];
        while let Ok(a) = stream.peek(&mut buf) {
            //checks if theres anything to read
            if a == 0 {
                continue;
            }
            if let Ok(h) = WalletMessageHeader::from_reader(stream) {
                write_in_log(
                    vec![format!(
                        "Received request {}",
                        h.message_name().replace('\0', "")
                    )],
                    sender_log.clone(),
                );

                match h.message_name().as_str() {
                    "getutxo\0\0\0\0\0" => {
                        Self::answer_utxo_request(node.clone(), stream)?;
                    }
                    "createtx\0\0\0\0" => {
                        Self::answer_tx_creation_request(
                            node.clone(),
                            stream,
                            network_listener.clone(),
                            sender_log.clone(),
                        )?;
                    }
                    "poirequest\0\0" => {
                        Self::answer_poi_request(node.clone(), stream)?;
                    }
                    "endconnect\0\0" => {
                        Self::close_connection_to_wallet(node, stream);
                        break;
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    }
}
