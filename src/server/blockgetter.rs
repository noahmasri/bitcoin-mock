//! Este modulo contiene un handler de la descarga de bloques en paralelo,
//! basado en la estructura de una Thread Pool especificada.

use crate::{
    server::{blockdownload::Blockchain, blocks::Block},
    utils::errors::DownloadError,
};
use std::{
    collections::{HashMap, HashSet},
    net::TcpStream,
    sync::{mpsc, Arc, Mutex},
    thread,
    time::Duration,
};

use indicatif::{ProgressBar, ProgressStyle};
/// Estructura que maneja la descarga de bloques en paralelo.
pub struct Blockgetter {
    workers: Vec<Worker>,
    tasks: HashSet<[u8; 32]>, //hashes of pending blocks
    receiver_blocks: mpsc::Receiver<Response>,
    sender_headers: mpsc::Sender<[u8; 32]>,
}
enum Response {
    HeaderToResend([u8; 32]),
    BlockToSave(Box<Block>),
}
struct Worker {
    thread: Option<thread::JoinHandle<()>>,
}

impl Blockgetter {
    /// Se crean los workers y se les asigna un stream, se crean los channels y se mandan los headers a los workers.
    /// Se devuelve un Blockgetter para que quien lo creo pueda recibir los bloques.
    /// # Errors
    ///
    /// * si no se puede mandar los headers por el channel.
    pub fn new(
        streams: &Vec<TcpStream>,
        headers: HashSet<[u8; 32]>,
    ) -> Result<Blockgetter, DownloadError> {
        let (sender_headers, receiver_headers) = mpsc::channel::<[u8; 32]>();
        let (sender_blocks, receiver_blocks) = mpsc::channel::<Response>();
        let receiver_header = Arc::new(Mutex::new(receiver_headers));
        let mut workers = Vec::with_capacity(streams.len());

        for i in streams {
            if let Ok(stream_clone) = i.try_clone() {
                if let Ok(worker) = Worker::new(
                    stream_clone,
                    Arc::clone(&receiver_header),
                    sender_blocks.clone(),
                ) {
                    workers.push(worker);
                };
            };
        }

        for header in &headers {
            sender_headers.send(*header)?;
        }

        drop(sender_blocks);
        drop(receiver_header);
        Ok(Blockgetter {
            workers,
            tasks: headers,
            receiver_blocks,
            sender_headers,
        })
    }

    /// Procesa las respuestas de los Workers tras hacer sus trabajos. Si recibe una respuesta,
    /// en base a estas o bien vuelve a mandar el header para que otro cumpla con el trabajo
    /// o bien recibe un bloque y lo agrega al vector a devolver.
    /// # Errors
    /// * No logra enviar el header del que no se pudo obtener el bloque
    pub fn receive_blocks(&mut self) -> Result<HashMap<[u8; 32], Block>, DownloadError> {
        let pb = ProgressBar::new(self.tasks.len() as u64);
        pb.set_style(ProgressStyle::with_template(
            "{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {pos:>7}/{len:7}, ({eta}) {msg}")?);
        let mut blocks: HashMap<[u8; 32], Block> = HashMap::new();
        while let Ok(response) = self.receiver_blocks.recv() {
            match response {
                Response::BlockToSave(b) => {
                    let header_hash = &b.header.hash();
                    self.tasks.remove(header_hash);
                    blocks.insert(*header_hash, *b);
                    if self.tasks.is_empty() {
                        break;
                    }
                }

                Response::HeaderToResend(h) => {
                    self.sender_headers.send(h)?;
                }
            }
            pb.set_position(blocks.len() as u64);
        }
        pb.finish_with_message("Download completed");
        Ok(blocks)
    }
}

impl Drop for Blockgetter {
    fn drop(&mut self) {
        for worker in &mut self.workers {
            if let Some(thread) = worker.thread.take() {
                if thread.join().is_err() {
                    println!("Failed to join worker");
                }
            }
        }
    }
}

fn process_peer_response(
    node: TcpStream,
    block_header: [u8; 32],
    sender_blocks: mpsc::Sender<Response>,
) -> Result<(), DownloadError> {
    match Blockchain::download_block(node, block_header) {
        Ok(block) => {
            sender_blocks.send(Response::BlockToSave(Box::new(block)))?;
        }
        Err(DownloadError::InvalidBlock) => {
            return Ok(());
        }
        Err(DownloadError::EofEncountered) => {
            sender_blocks.send(Response::HeaderToResend(block_header))?;
            return Err(DownloadError::EofEncountered);
        }
        Err(_) => {
            sender_blocks.send(Response::HeaderToResend(block_header))?;
            thread::sleep(Duration::from_secs(2));
        }
    }

    Ok(())
}

fn process_worker(
    stream: TcpStream,
    receiver: Arc<Mutex<mpsc::Receiver<[u8; 32]>>>,
    sender_blocks: mpsc::Sender<Response>,
) {
    loop {
        let node = match stream.try_clone() {
            Ok(n) => n,
            Err(_) => break,
        };

        let message = match receiver.lock() {
            Ok(m) => m,
            Err(_e) => break,
        };
        match message.try_recv() {
            Ok(header) => {
                drop(message);
                if process_peer_response(node, header, sender_blocks.clone()).is_err() {
                    break;
                }
            }
            Err(_) => {
                drop(message);
                drop(sender_blocks);
                break;
            }
        }
    }
}

impl Worker {
    fn new(
        stream: TcpStream,
        receiver_headers: Arc<Mutex<mpsc::Receiver<[u8; 32]>>>,
        sender_blocks: mpsc::Sender<Response>,
    ) -> Result<Worker, DownloadError> {
        let node = stream.try_clone()?;
        let clone_sender_blocks = sender_blocks.clone();
        let thread = thread::spawn(move || {
            process_worker(node, receiver_headers, clone_sender_blocks);
        });
        drop(sender_blocks);

        Ok(Worker {
            thread: Some(thread),
        })
    }
}
