use crate::utils::wallet_messages::{BlockInclusion, IncomingTx};
use crate::utils::{
    errors::{DownloadError, NodeError},
    tx::Transaction,
};
use crate::{
    server::{
        blocks::Block,
        logfile::write_in_log,
        messages::{GetDataPayload, InvMessage, Message, MessageHeader, PongMessage, TxMessage},
        node::Node,
        utxos::get_pkhash_from_pkscript,
    },
    utils::errors::MessageError,
};
use std::{
    cmp::{max, min},
    collections::HashSet,
    io::{Read, Write},
    net::TcpStream,
    sync::{mpsc, Arc, Mutex},
    thread,
};

use super::blockdownload::GENESIS_BLOCK_HASH;
use super::{
    blocks::BlockHeader,
    messages::{AddrMessage, Address, BlockMessage, GetHeadersPayload, HeadersMessage},
};

/// Estructura de listener, que contiene canales de comunicacion con sus trabajadores, y mantiene un registro de la
/// informacion entrante para evitar anunciar multiples veces.
pub struct NetworkListener {
    listeners: Vec<Listener>,
    tx_data: mpsc::Sender<Data>,
    block_register: HashSet<[u8; 32]>,
    tx_register: HashSet<[u8; 32]>,
    node: Arc<Mutex<Node>>,
}

struct Listener {
    thread: Option<thread::JoinHandle<()>>,
}

pub enum Data {
    BlockToCheck(Box<Block>),
    TxToCheck(Transaction),
}

impl NetworkListener {
    /// Recibe un mutex de un nodo y genera una estructura que se comunica y handlea todos los mensajes
    /// de la blockchain, actualizando dinamicamente la estructura recibida en base a la informacion recibida
    pub fn new(
        node: Arc<Mutex<Node>>,
        sender_log: Option<mpsc::Sender<String>>,
    ) -> Result<(NetworkListener, mpsc::Receiver<Data>), NodeError> {
        let (tx_data, rx_data) = mpsc::channel::<Data>();
        let block_register: HashSet<[u8; 32]> = HashSet::new();
        let tx_register: HashSet<[u8; 32]> = HashSet::new();
        let mut listeners = Vec::new();
        let locked_node = node.lock()?;

        for s in locked_node.peers.iter() {
            if let Ok(stream_clone) = s.try_clone() {
                if let Ok(worker) = Listener::new(
                    stream_clone,
                    tx_data.clone(),
                    node.clone(),
                    sender_log.clone(),
                ) {
                    listeners.push(worker);
                };
            };
        }

        drop(locked_node);

        Ok((
            NetworkListener {
                listeners,
                tx_data,
                block_register,
                tx_register,
                node,
            },
            rx_data,
        ))
    }

    pub fn add_new_peer(
        net_listener: Arc<Mutex<NetworkListener>>,
        peer: TcpStream,
        sender_log: Option<mpsc::Sender<String>>,
    ) {
        if let Ok(mut net_lock) = net_listener.lock() {
            if let Ok(stream_clone) = peer.try_clone() {
                if let Ok(worker) = Listener::new(
                    stream_clone,
                    net_lock.tx_data.clone(),
                    net_lock.node.clone(),
                    sender_log,
                ) {
                    net_lock.listeners.push(worker);
                };
            };
        }
    }

    fn check_transaction(net_listener: Arc<Mutex<NetworkListener>>, tx: Transaction) {
        let hash = tx.hash();

        if let Ok(mut net_lock) = net_listener.lock() {
            if net_lock.tx_register.contains(&hash) {
                // tx was announced already
                return;
            }

            net_lock.tx_register.insert(hash);
            let mut my_outs: Vec<(IncomingTx, [u8; 20])> = Vec::new();

            if let Ok(mut locked_node) = net_lock.node.lock() {
                for (i, out) in (0..).zip(tx.tx_out.iter()) {
                    if let Ok(pk_receiver) = get_pkhash_from_pkscript(&out.pk_script) {
                        if locked_node.accounts.get(&pk_receiver).is_some() {
                            let in_tx = IncomingTx::new(hash, i, out.value);
                            my_outs.push((in_tx, pk_receiver));
                        }
                    }
                }

                locked_node.announce_incoming_txs(my_outs);
            }
            net_lock.broadcast_transaction(hash);
        }
    }

    fn check_block(net_listener: Arc<Mutex<NetworkListener>>, block: Block) {
        let block_hash = block.header.hash();
        if let Ok(mut locked) = net_listener.lock() {
            let node = locked.node.clone();
            if locked.block_register.contains(&block_hash) {
                // block was announced already
                return;
            }

            locked.block_register.insert(block_hash);
            locked.broadcast_block(block_hash);
            drop(locked);

            let mut tx_to_announce: Vec<(BlockInclusion, [u8; 20])> = Vec::new();
            if let Ok(mut locked_node) = node.lock() {
                if !locked_node.blockchain.is_block_included(block.clone()) {
                    //recorrer todas las tx del bloque viendo si es parte de las broadcasted tx
                    //si lo es, avisar a la wallet q la creo que ya la incluyeron
                    for tx in block.txs.iter() {
                        locked_node.check_if_announcement_is_required(
                            block.height(),
                            tx.hash(),
                            &mut tx_to_announce,
                            tx,
                        );
                    }
                }
                locked_node.announce_inclusion_in_block(tx_to_announce);
            };
        }
    }

    /// Lee del canal de comunicacion con los listeners, y verifica cual es la informacion recibida.
    /// En base al caso, hace los chequeos y avisos requeridos por el protocolo.
    pub fn receive_data(net_listener: Arc<Mutex<NetworkListener>>, rx_data: mpsc::Receiver<Data>) {
        while let Ok(data) = rx_data.recv() {
            match data {
                Data::BlockToCheck(block) => {
                    NetworkListener::check_block(net_listener.clone(), *block);
                }

                Data::TxToCheck(tx) => {
                    NetworkListener::check_transaction(net_listener.clone(), tx);
                }
            }
        }
    }

    fn transmit_inv_to_all_peers(&self, id: [u8; 32], data_type: u32) {
        if let Ok(locked) = self.node.lock() {
            let message_to_transmit = InvMessage::new(vec![(data_type, id)]);

            for stream in &locked.peers {
                if let Ok(mut cloned) = stream.try_clone() {
                    if message_to_transmit.send_message(&mut cloned).is_err() {
                        continue;
                    }
                }
            }
        }
    }
    /// Recibe el transaction id y crea un mensaje inv para luego enviarlo 32 veces por el channel
    /// hacia los listeners para que quienes lo reciban lo envien al peer que tienen asignado.
    ///
    pub fn broadcast_transaction(&self, txid: [u8; 32]) {
        self.transmit_inv_to_all_peers(txid, 1);
    }

    pub fn broadcast_block(&self, block_hash: [u8; 32]) {
        self.transmit_inv_to_all_peers(block_hash, 2);
    }
}

impl Drop for NetworkListener {
    fn drop(&mut self) {
        for worker in &mut self.listeners {
            if let Some(thread) = worker.thread.take() {
                if thread.join().is_err() {
                    println!("Failed to join worker");
                }
            }
        }
    }
}

impl Listener {
    fn new(
        stream: TcpStream,
        tx_data: mpsc::Sender<Data>,
        node: Arc<Mutex<Node>>,
        sender_log: Option<mpsc::Sender<String>>,
    ) -> Result<Listener, DownloadError> {
        let thread =
            thread::spawn(
                move || {
                    if Self::process_worker(stream, tx_data, node, sender_log).is_err() {}
                },
            );

        Ok(Listener {
            thread: Some(thread),
        })
    }

    fn send_addr(stream: &mut TcpStream) -> Result<(), MessageError> {
        if let Ok(address) = Address::new() {
            let msg = AddrMessage::new(vec![address]);
            msg.send_message(stream)?;
        }
        Ok(())
    }

    fn process_worker(
        stream: TcpStream,
        tx_data: mpsc::Sender<Data>,
        node: Arc<Mutex<Node>>,
        sender_log: Option<mpsc::Sender<String>>,
    ) -> Result<(), DownloadError> {
        if let Ok(mut stream_clone) = stream.try_clone() {
            Listener::send_addr(&mut stream_clone)?;
        };

        loop {
            let mut stream_clone = match stream.try_clone() {
                Ok(n) => n,
                Err(_) => break,
            };
            if Self::receive_messages(
                &mut stream_clone,
                tx_data.clone(),
                node.clone(),
                sender_log.clone(),
            )
            .is_err()
            {
                break;
            }
        }
        Ok(())
    }

    fn send_response_to_inv(
        header: MessageHeader,
        stream: &mut TcpStream,
    ) -> Result<(), DownloadError> {
        let mut payload: Vec<u8> = Vec::new();
        for _ in 0..header.payload_size {
            let mut buf: [u8; 1] = [0];
            stream.read_exact(&mut buf)?;
            let byte = <u8>::from_le_bytes(buf);
            payload.push(byte);
        }

        let gd_header = MessageHeader::new("getdata\0\0\0\0\0", Some(payload.clone()));
        stream.write_all(&gd_header.as_bytes())?;
        stream.write_all(&payload)?;
        Ok(())
    }

    fn send_response_to_get_data(
        node: Arc<Mutex<Node>>,
        stream: &mut TcpStream,
    ) -> Result<(), DownloadError> {
        let data_payload = GetDataPayload::parse_data_entries(stream)?;
        for (entry_type, entry) in data_payload.inventory_entries {
            match entry_type {
                1 => {
                    let locked_node = node.lock()?;
                    if let Some((tx, _)) = locked_node.broadcasted_tx.get(&entry) {
                        let tx_message = TxMessage::new(tx);
                        tx_message.send_message(stream)?;
                    }
                    drop(locked_node);
                }
                2 => {
                    let locked_node = node.lock()?;
                    if let Some(block) = locked_node.blockchain.blocks.get(&entry) {
                        let block_message = BlockMessage::new(block);
                        block_message.send_message(stream)?;
                    }
                    drop(locked_node);
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn send_pong(stream: &mut TcpStream) -> Result<(), DownloadError> {
        let pong_msg = PongMessage::new(stream)?;
        stream.write_all(&pong_msg.as_bytes())?;
        Ok(())
    }

    fn send_response_to_get_headers(
        stream: &mut TcpStream,
        node: Arc<Mutex<Node>>,
    ) -> Result<(), DownloadError> {
        let headers_payload = GetHeadersPayload::from_bytes(stream)?;
        let locked_node = node.lock()?;
        let start;
        if headers_payload.last_header_hash == GENESIS_BLOCK_HASH {
            start = 0;
        } else if let Some(last_rcv) = locked_node
            .blockchain
            .block_headers
            .map
            .get(&headers_payload.last_header_hash)
        {
            start = *last_rcv + 1;
        } else {
            return Ok(());
        }

        let mut count = 0;
        if headers_payload.stopping_hash == [0; 32] {
            count = 2000;
        } else if let Some(stop) = locked_node
            .blockchain
            .block_headers
            .map
            .get(&headers_payload.stopping_hash)
        {
            count = max(min(2000, stop - start), 0);
        }
        let headers_to_send: Vec<BlockHeader> = locked_node
            .blockchain
            .block_headers
            .list
            .iter()
            .skip(start)
            .take(count)
            .cloned()
            .collect();

        drop(locked_node);
        let msg = HeadersMessage::new(headers_to_send);
        msg.send_message(stream)?;

        Ok(())
    }

    fn receive_messages(
        stream: &mut TcpStream,
        tx_data: mpsc::Sender<Data>,
        node: Arc<Mutex<Node>>,
        sender_log: Option<mpsc::Sender<String>>,
    ) -> Result<(), DownloadError> {
        let header = MessageHeader::from_bytes(stream)?;
        let message_command_name = header.is_message();
        write_in_log(
            vec![format!(
                "Received {} message from peer",
                message_command_name.replace('\0', "")
            )],
            sender_log,
        );
        match message_command_name.as_str() {
            "inv\0\0\0\0\0\0\0\0\0" => {
                Self::send_response_to_inv(header, stream)?;
            }
            "tx\0\0\0\0\0\0\0\0\0\0" => {
                let tx = Transaction::parse_transaction(stream)?;
                tx_data.send(Data::TxToCheck(tx))?;
            }
            "block\0\0\0\0\0\0\0" => {
                let block = Block::parse_blocks_message(stream)?;
                tx_data.send(Data::BlockToCheck(Box::new(block)))?;
            }
            "getdata\0\0\0\0\0" => {
                Self::send_response_to_get_data(node, stream)?;
            }
            "ping\0\0\0\0\0\0\0\0" => {
                Self::send_pong(stream)?;
            }
            "getheaders\0\0" => {
                Self::send_response_to_get_headers(stream, node)?;
            }
            _ => header.ignore_payload(stream)?,
        }
        Ok(())
    }
}
