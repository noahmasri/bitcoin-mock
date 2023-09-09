//! Este modulo contiene todas las funciones necesarias para poder conectarse
//! con una direccion DNS para realizar Peer Discovery, y establecer una
//! conexion con los nodos

use crate::server::logfile::write_in_log;
use crate::server::messages::{Message, VerackMessage, VersionMessage};
use crate::utils::errors::{HandshakeError, MessageError, SocketError};
use chrono::Local;
use rand::Rng;
use std::io::Write;
use std::net::{IpAddr, TcpStream, ToSocketAddrs};
use std::sync::mpsc;
use std::sync::Arc;
use std::sync::Mutex;
use std::thread::{self, JoinHandle};

///Obtiene las direcciones IP y puertos de los DNS en forma de tupla
pub fn get_ips_address(domain: &str, port: u16) -> Result<Vec<(IpAddr, u16)>, SocketError> {
    let mut addresses = Vec::new();
    let sock_iter = (domain, port).to_socket_addrs()?;
    for sock in sock_iter {
        addresses.push((sock.ip(), sock.port()));
    }

    Ok(addresses)
}

pub fn handle_joins_and_log(
    threads: Vec<JoinHandle<()>>,
    streams: Arc<Mutex<Vec<TcpStream>>>,
    sender_log: Option<mpsc::Sender<String>>,
) -> Result<Vec<TcpStream>, HandshakeError> {
    for handle in threads {
        if handle.join().is_err() {
            write_in_log(
                vec![String::from(
                    "Error: HandshakeError::JoinError, couldn't join after handshake",
                )],
                sender_log,
            );
            return Err(HandshakeError::JoinError);
        }
    }

    let mut vec = streams.lock()?;
    if vec.is_empty() {
        write_in_log(
            vec![format!(
                "Error: HandshakeError::CouldntConnectToPeers, failed to handshake"
            )],
            sender_log,
        );
        return Err(HandshakeError::CouldntConnectToPeers);
    }

    write_in_log(
        vec![format!(
            "Finished handshake, having now {} peers",
            vec.len().clone()
        )],
        sender_log,
    );

    Ok(std::mem::take(&mut vec))
}

/// Realiza handshake a todos los nodos pasados por argumento.
/// Se pasa por argumento un vector con direcciones del nodo con el que se va a comunicar, tambien su vesion y direccion,a si como altura inicial de bloques a descargar
/// Devuelve un vector con los TcpStream de los nodos con los que se contacto o un error de tipo HandshakeError
/// # Errors
/// * error de join de thread
/// * no se puede conectar con otros nodos
pub fn handshakes(
    version: i32,
    my_address: (IpAddr, u16),
    start_height: i32,
    addresses: Vec<(IpAddr, u16)>,
    sender_log: Option<mpsc::Sender<String>>,
) -> Result<Vec<TcpStream>, HandshakeError> {
    let streams: Vec<TcpStream> = vec![];
    let s: Arc<Mutex<Vec<TcpStream>>> = Arc::new(Mutex::new(streams));
    let mut threads = Vec::new();

    for address in addresses {
        let shared_s = s.clone();

        let handle = thread::spawn(move || {
            if let Ok(stream) = make_handshake(version, my_address, start_height, address) {
                if let Ok(mut locked_stream) = shared_s.lock() {
                    locked_stream.push(stream);
                };
            };
        });
        threads.push(handle);
    }

    handle_joins_and_log(threads, s, sender_log)
}
/// Realiza el handshake con un nodo en particular pasado como tupla IP y puerto.
/// Se pasa por argumento direccion del nodo con el que se va a comunicar, tambien su vesion y direccion,a si como altura inicial de bloques a descargar
/// Devuelve el TcpStream del nodos con el que se contacto o un error de tipo MessageError
/// # Error
/// * si no se puede conectar al nodo
/// * no pudo generar el version message del otro nodo
/// * si el mensaje del otro nodo no es valido
/// * si no puede enviar mensajes al otro nodo
pub fn make_handshake(
    version: i32,
    my_address: (IpAddr, u16),
    start_height: i32,
    address: (IpAddr, u16),
) -> Result<TcpStream, MessageError> {
    let now = Local::now();
    let timestamp = now.timestamp();
    let mut my_socket = TcpStream::connect(address)?;

    let my_version_message = VersionMessage::new(
        (version, 0x00, timestamp),
        (0x01, address.0, address.1),
        (0x00, my_address.0, my_address.1),
        rand::thread_rng().gen(),
        vec![],
        start_height,
        0x00,
    );

    my_version_message.send_message(&mut my_socket)?;
    let other_node_version_message = VersionMessage::from_bytes(&mut my_socket)?;
    my_version_message.check_valid_version(&other_node_version_message)?;

    my_socket.write_all(&VerackMessage::new().as_bytes())?;
    VerackMessage::check_verack(&mut my_socket)?;
    Ok(my_socket)
}

pub fn wait_for_handshake(
    stream: &mut TcpStream,
    my_address: (IpAddr, u16),
) -> Result<(), MessageError> {
    let version_msg = VersionMessage::from_bytes(stream)?;
    let now = Local::now();
    let timestamp = now.timestamp();

    let my_version_message = VersionMessage::new(
        (70015, 0x00, timestamp),
        (
            version_msg.payload.sender_services,
            version_msg.payload.sender_ip,
            version_msg.payload.sender_port,
        ),
        (0x00, my_address.0, my_address.1),
        rand::thread_rng().gen(),
        vec![],
        0,
        0x00,
    );
    let mut clone_stream = stream.try_clone()?;
    my_version_message.send_message(&mut clone_stream)?;
    VerackMessage::check_verack(&mut clone_stream)?;
    let verack_msg = VerackMessage::new();
    verack_msg.send_message(stream)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    #[test]
    fn ip_addresses_and_ports_are_fetch_correctly() -> Result<(), SocketError> {
        let addresses = get_ips_address("seed.testnet.bitcoin.sprovoost.nl", 18333)?;
        assert!(!addresses.is_empty());
        for addr in addresses {
            assert!(addr.1 != 0);
            assert!(addr.0.is_ipv4() || addr.0.is_ipv6());
        }
        Ok(())
    }
    #[test]
    fn cannot_fetch_from_an_invalid_domain() {
        let resulting_vec = get_ips_address("thisisnotavaliddomain", 80);
        assert!(matches!(resulting_vec, Err(SocketError::InputOutputError)));
    }

    #[test]
    fn can_generate_multiple_connections() -> Result<(), SocketError> {
        let resulting_vec = get_ips_address("seed.testnet.bitcoin.sprovoost.nl", 18333)?;

        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let port = 1001;

        assert!(handshakes(70015, (ip, port), 0, resulting_vec, None).is_ok());
        Ok(())
    }
}
