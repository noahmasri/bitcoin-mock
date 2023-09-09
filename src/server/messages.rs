//! Este modulo contiene numerosas estructuras
//! para el envio y el recibo de mensajes. Esto incluye
//! el parseo de los mensajes a partir de bytes recibidos,
//! como tambien la generacion de un mensaje en formato de bytes
//! a partir de la estructura

use crate::server::blocks::BlockHeader;
use crate::utils::{
    compact_size::{make_compact, parse_compact},
    errors::{self, MessageError},
    tx::Transaction,
};
use bitcoin_hashes::{sha256d, Hash};
use chrono::Utc;
use std::io::Read;
use std::io::Write;
use std::net::IpAddr;

use super::blocks::Block;
pub const TESTNET_PORT: u16 = 18333;
const VERACK: [u8; 12] = [
    0x76, 0x65, 0x72, 0x61, 0x63, 0x6b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

const TESTNET: [u8; 4] = [0x0b, 0x11, 0x09, 0x07];

/// Estructura de encabezado de mensaje tomada de la documentacion de bitcoin,
/// util para la creacion de mensajes a enviar
pub struct MessageHeader {
    start_string: [u8; 4],
    command_name: Vec<u8>,
    pub payload_size: u32,
    checksum: [u8; 4],
}

impl MessageHeader {
    fn get_checksum(payload: Vec<u8>) -> [u8; 4] {
        let hash = sha256d::Hash::hash(payload.as_slice());
        let hash_val = hash.as_byte_array();
        let mut first = [0u8; 4];
        first.copy_from_slice(&hash_val[..4]);
        first
    }

    /// A partir del nombre de un comando y un payload opcional, devuelve el header del mensaje deseado.
    #[must_use]
    pub fn new(command_name: &str, payload: Option<Vec<u8>>) -> MessageHeader {
        let start_string: [u8; 4] = TESTNET; //startstring de testnet'
        let mut command_bytes = vec![0; 12];
        command_bytes[..command_name.len()].copy_from_slice(command_name.as_bytes());

        let payload_size: u32;
        let checksum = if let Some(p) = payload {
            payload_size = p.len() as u32;
            MessageHeader::get_checksum(p)
        } else {
            payload_size = 0;
            MessageHeader::get_checksum(Vec::new())
        };
        MessageHeader {
            start_string,
            command_name: command_bytes,
            payload_size,
            checksum,
        }
    }

    /// Traduce el `MessageHeader` a su fomato en bytes.
    #[must_use]
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut buf_message = Vec::new();
        buf_message.extend_from_slice(&self.start_string);
        buf_message.extend(&self.command_name);
        buf_message.extend_from_slice(&(self.payload_size).to_le_bytes());
        buf_message.extend_from_slice(&self.checksum);
        buf_message
    }

    /// Obtiene el header de un mensaje a partir de un reader, que en nuestro caso sera
    /// un stream, realizando los parseos y conversiones necesarias.
    /// # Errors
    /// * al intentar leer del stream, no se encuentra la cantidad de bytes pedida. El error obtenido
    /// es un MessageError::IncompleteMessage
    pub fn from_bytes(stream: &mut dyn Read) -> Result<MessageHeader, MessageError> {
        let mut buf_start_string: [u8; 4] = [0; 4];
        let mut buf_command_name: [u8; 12] = [0; 12];
        let mut buf_payload_size: [u8; 4] = [0; 4];
        let mut buf_checksum: [u8; 4] = [0; 4];

        stream.read_exact(&mut buf_start_string)?;
        stream.read_exact(&mut buf_command_name)?;
        stream.read_exact(&mut buf_payload_size)?;
        stream.read_exact(&mut buf_checksum)?;

        Ok(MessageHeader {
            start_string: buf_start_string,
            command_name: buf_command_name.to_vec(),
            payload_size: <u32>::from_le_bytes(buf_payload_size),
            checksum: buf_checksum,
        })
    }

    /// Devuelve el nombre del comando al que pertenece en formato string
    #[must_use]
    pub fn is_message(&self) -> String {
        let vec_char: Vec<char> = self.command_name.iter().map(|&x| x as char).collect();
        let string_data: String = vec_char.into_iter().collect();
        string_data
    }

    /// Lee del stream la cantidad de bytes que indica que tiene como tamano el payload,
    /// y no los almacena en ningun lado.
    /// # Errors
    /// * al intentar leer del stream, no se encuentra la cantidad de bytes pedida. El error obtenido
    /// es un MessageError::IncompleteMessage
    pub fn ignore_payload(&self, stream: &mut dyn Read) -> Result<(), MessageError> {
        if self.payload_size != 0 {
            for _ in 0..self.payload_size {
                let mut _buf: [u8; 1] = [0; 1];
                stream.read_exact(&mut _buf)?;
            }
        }

        Ok(())
    }
}

/// Este trait Message contiene dos funciones que caracterizan a los mensajes:
/// * se pueden pasar a bytes
/// * se pueden pasar por un TcpStream u otra estructura que implemente el trait
/// write. De esta manera se permite la comunicacion con otras entidades
/// # Errors
/// * al intentar escribir en el Stream, la contraparte cerro la conexion
/// * al intentar escribir en el Stream, la contraparte cerro el extremo de escritura
/// * al intentar escribir en el Stream, no hay espacio disponible en el buffer de salida
/// En todos los casos, el error obtenido es un MessageError::CouldntSendMessage
pub trait Message {
    fn as_bytes(&self) -> Vec<u8>;
    fn send_message(&self, stream: &mut dyn Write) -> Result<(), errors::MessageError> {
        let buf_message = self.as_bytes();
        stream.write_all(&buf_message)?;
        Ok(())
    }
}

pub struct PongMessage {
    header: MessageHeader,
    nonce: [u8; 8],
}

impl PongMessage {
    /// Crea una nueva instancia del struct PongMessage y la devuelve.
    ///
    /// # Errors
    /// * No se puede leer del stream la cantidad de bytes pedida. El error que devuelve es MessageError::IncompleteMessage
    pub fn new(stream: &mut dyn Read) -> Result<PongMessage, MessageError> {
        let ping_nonce = Self::get_ping_nonce(stream)?;
        let message_header = MessageHeader::new("pong\0\0\0\0\0\0\0\0", Some(ping_nonce.to_vec()));
        Ok(Self {
            header: message_header,
            nonce: ping_nonce,
        })
    }

    fn get_ping_nonce(stream: &mut dyn Read) -> Result<[u8; 8], MessageError> {
        let mut buf_nonce: [u8; 8] = [0; 8];
        stream.read_exact(&mut buf_nonce)?;
        Ok(buf_nonce)
    }
}

impl Message for PongMessage {
    fn as_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend(&self.header.as_bytes());
        buf.extend(&self.nonce);
        buf
    }
}

/// Estructura que contiene los campos del payload del version message, requeridos para el handshake
#[derive(Debug, Clone)]
pub struct VersionPayload {
    version: i32,
    services: u64,
    timestamp: i64,
    receiver_services: u64,
    receiver_ip: IpAddr,
    receiver_port: u16,
    pub sender_services: u64,
    pub sender_ip: IpAddr,
    pub sender_port: u16,
    nonce: u64,
    user_agent: Vec<u8>,
    start_height: i32,
    relay: u8,
}

impl VersionPayload {
    /// Genera un Version Payload con los parametros necesarios enviados como argumento a la funcion
    pub fn new(
        (version, services, timestamp): (i32, u64, i64),
        (receiver_services, receiver_ip, receiver_port): (u64, IpAddr, u16),
        (sender_services, sender_ip, sender_port): (u64, IpAddr, u16),
        nonce: u64,
        user_agent: Vec<u8>,
        start_height: i32,
        relay: u8,
    ) -> Self {
        VersionPayload {
            version,
            services,
            timestamp,
            receiver_services,
            receiver_ip,
            receiver_port,
            sender_services,
            sender_ip,
            sender_port,
            nonce,
            user_agent,
            start_height,
            relay,
        }
    }

    /// Genera un Version Payload con los campos pasados como arrays de bytes
    pub fn new_from_buf(
        (version, services, timestamp): ([u8; 4], [u8; 8], [u8; 8]),
        (receiver_services, receiver_ip, receiver_port): ([u8; 8], [u8; 16], [u8; 2]),
        (sender_services, sender_ip, sender_port): ([u8; 8], [u8; 16], [u8; 2]),
        nonce: [u8; 8],
        user_agent: Vec<u8>,
        start_height: [u8; 4],
        relay: [u8; 1],
    ) -> Self {
        VersionPayload {
            version: <i32>::from_le_bytes(version),
            services: <u64>::from_le_bytes(services),
            timestamp: <i64>::from_le_bytes(timestamp),
            receiver_services: <u64>::from_le_bytes(receiver_services),
            receiver_ip: <IpAddr>::from(receiver_ip),
            receiver_port: <u16>::from_be_bytes(receiver_port),
            sender_services: <u64>::from_le_bytes(sender_services),
            sender_ip: <IpAddr>::from(sender_ip),
            sender_port: <u16>::from_be_bytes(sender_port),
            nonce: u64::from_le_bytes(nonce),
            user_agent,
            start_height: i32::from_le_bytes(start_height),
            relay: relay[0],
        }
    }

    /// Devuelve todo el Version Payload como un vector de bytes, respetando la endianness
    /// declarada en la documentacion
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut buf_message = Vec::new();
        buf_message.extend_from_slice(&(self.version).to_le_bytes());
        buf_message.extend_from_slice(&(self.services).to_le_bytes());
        buf_message.extend_from_slice(&(self.timestamp).to_le_bytes());
        buf_message.extend_from_slice(&(self.receiver_services).to_le_bytes());
        let receiver_bytes = match self.receiver_ip {
            IpAddr::V6(ipv6) => u128::from(ipv6).to_be_bytes(),
            IpAddr::V4(ipv4) => u128::from(ipv4.to_ipv6_compatible()).to_be_bytes(),
        };
        buf_message.extend_from_slice(&receiver_bytes);
        buf_message.extend_from_slice(&(self.receiver_port).to_be_bytes());
        buf_message.extend_from_slice(&(self.sender_services).to_le_bytes());
        let sender_bytes = match self.sender_ip {
            IpAddr::V6(ipv6) => u128::from(ipv6).to_be_bytes(),
            IpAddr::V4(ipv4) => u128::from(ipv4.to_ipv6_compatible()).to_be_bytes(),
        };
        buf_message.extend_from_slice(&sender_bytes);
        buf_message.extend_from_slice(&(self.sender_port).to_be_bytes());
        buf_message.extend_from_slice(&(self.nonce).to_le_bytes());
        buf_message.extend_from_slice(&((self.user_agent.len()) as u8).to_le_bytes());
        buf_message.extend_from_slice(&(self.user_agent));
        buf_message.extend_from_slice(&(self.start_height).to_le_bytes());
        buf_message.push(self.relay);
        buf_message
    }

    /// Construye un Version Payload a partir de la lectura de un Stream, u otro tipo de
    /// dato que implemente el trait Read
    /// # Errors
    /// * al intentar leer del stream, no se encuentra la cantidad de bytes pedida. El error obtenido
    /// es un MessageError::IncompleteMessage
    pub fn from_bytes(stream: &mut dyn Read) -> Result<VersionPayload, MessageError> {
        let mut buf_version: [u8; 4] = [0; 4];
        let mut buf_service: [u8; 8] = [0; 8];
        let mut buf_timestamp: [u8; 8] = [0; 8];
        let mut buf_rec_serv: [u8; 8] = [0; 8];
        let mut buf_rec_ip: [u8; 16] = [0; 16];
        let mut buf_rec_port: [u8; 2] = [0; 2];
        let mut buf_send_serv: [u8; 8] = [0; 8];
        let mut buf_send_ip: [u8; 16] = [0; 16];
        let mut buf_send_port: [u8; 2] = [0; 2];
        let mut buf_nonce: [u8; 8] = [0; 8];

        stream.read_exact(&mut buf_version)?;
        stream.read_exact(&mut buf_service)?;
        stream.read_exact(&mut buf_timestamp)?;
        stream.read_exact(&mut buf_rec_serv)?;
        stream.read_exact(&mut buf_rec_ip)?;
        stream.read_exact(&mut buf_rec_port)?;
        stream.read_exact(&mut buf_send_serv)?;
        stream.read_exact(&mut buf_send_ip)?;
        stream.read_exact(&mut buf_send_port)?;
        stream.read_exact(&mut buf_nonce)?;

        let user_agent_size = parse_compact(stream)?;
        let mut buf_user_agent = vec![0; user_agent_size];
        stream.read_exact(&mut buf_user_agent)?;
        let mut buf_start_height: [u8; 4] = [0; 4];
        stream.read_exact(&mut buf_start_height)?;
        let mut buf_relay: [u8; 1] = [0; 1];
        match stream.read_exact(&mut buf_relay) {
            Ok(_) => {}
            Err(_) => buf_relay = [0x01],
        };

        Ok(VersionPayload::new_from_buf(
            (buf_version, buf_service, buf_timestamp),
            (buf_rec_serv, buf_rec_ip, buf_rec_port),
            (buf_send_serv, buf_send_ip, buf_send_port),
            buf_nonce,
            buf_user_agent,
            buf_start_height,
            buf_relay,
        ))
    }
}

/// Estructura del Version Message del protocolo de comunicacion bitcoin
pub struct VersionMessage {
    pub header: MessageHeader,
    pub payload: VersionPayload,
}

impl Message for VersionMessage {
    fn as_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer.extend(&self.header.as_bytes());
        buffer.extend(&self.payload.as_bytes());
        buffer
    }
}

impl VersionMessage {
    fn new_internal(payload: VersionPayload) -> Self {
        let payload_bytes = payload.as_bytes();
        let message_header = MessageHeader::new("version\0\0\0\0\0", Some(payload_bytes));
        Self {
            header: message_header,
            payload,
        }
    }

    /// Crea una nueva instancia de VersionMessage.
    /// Recibe todo campo especificado en la documentacion
    /// de bitcoin para el mensaje.
    pub fn new(
        (version, services, timestamp): (i32, u64, i64),
        (receiver_services, receiver_ip, receiver_port): (u64, IpAddr, u16),
        (sender_services, sender_ip, sender_port): (u64, IpAddr, u16),
        nonce: u64,
        user_agent: Vec<u8>,
        start_height: i32,
        relay: u8,
    ) -> Self {
        let payload = VersionPayload::new(
            (version, services, timestamp),
            (receiver_services, receiver_ip, receiver_port),
            (sender_services, sender_ip, sender_port),
            nonce,
            user_agent,
            start_height,
            relay,
        );
        Self::new_internal(payload)
    }

    /// Crea una nueva instancia de VersionMessage, recibiendo todo campo especificado en la documentacion
    /// de bitcoin para el mensaje en formato array de bytes
    pub fn new_from_buf(
        (version, services, timestamp): ([u8; 4], [u8; 8], [u8; 8]),
        (receiver_services, receiver_ip, receiver_port): ([u8; 8], [u8; 16], [u8; 2]),
        (sender_services, sender_ip, sender_port): ([u8; 8], [u8; 16], [u8; 2]),
        nonce: [u8; 8],
        user_agent: Vec<u8>,
        start_height: [u8; 4],
        relay: [u8; 1],
    ) -> Self {
        let payload = VersionPayload::new_from_buf(
            (version, services, timestamp),
            (receiver_services, receiver_ip, receiver_port),
            (sender_services, sender_ip, sender_port),
            nonce,
            user_agent,
            start_height,
            relay,
        );
        Self::new_internal(payload)
    }

    /// Crea una nueva instancia de Version Message, leyendo todos los campos de un tipo de dato
    /// que implemente el trait read.
    /// # Errors
    /// * al intentar leer del stream, no se encuentra la cantidad de bytes pedida. El error obtenido
    /// es un MessageError::IncompleteMessage
    pub fn from_bytes(stream: &mut dyn Read) -> Result<Self, MessageError> {
        let header = MessageHeader::from_bytes(stream)?;
        let payload = VersionPayload::from_bytes(stream)?;

        Ok(VersionMessage { header, payload })
    }

    fn is_more_than_two_hours(time: i64) -> bool {
        let now = Utc::now();
        let timestamp = now.timestamp();
        time - timestamp > (2 * 60 * 60)
    }

    /// Chequea que el mensaje recibido sea valido. Un mensaje es valido si el nonce recibido
    /// es distinto al mandado por el usuario, y si el timestamp es menor que dos horas en el futuro
    /// # Errors
    /// * el mensaje no cumple con el criterio de validez. Devuelve MessageError::InvalidVersionMessage
    pub fn check_valid_version(&self, other_vm: &Self) -> Result<(), MessageError> {
        if Self::is_more_than_two_hours(other_vm.payload.timestamp)
            || self.payload.nonce == other_vm.payload.nonce
        {
            return Err(MessageError::InvalidVersionMessage);
        }
        Ok(())
    }
}

/// Estructura del Verack Message del protocolo de comunicacion bitcoin
pub struct VerackMessage {
    header: MessageHeader,
}

impl Message for VerackMessage {
    fn as_bytes(&self) -> Vec<u8> {
        self.header.as_bytes()
    }
}
impl Default for VerackMessage {
    fn default() -> Self {
        Self::new()
    }
}

impl VerackMessage {
    /// Crea una nueva instancia de VerackMessage.
    pub fn new() -> Self {
        Self {
            header: MessageHeader::new("verack\0\0\0\0\0\0", None),
        }
    }

    /// Chequea que el mensaje recibido sea uno de este tipo.
    ///
    /// # Errors
    /// * si no es de este tipo, es decir, si el mensaje recibido tiene payload, o
    /// si su nombre de comando no es verack + null padding.
    pub fn check_verack(stream: &mut dyn Read) -> Result<(), MessageError> {
        let verack = MessageHeader::from_bytes(stream)?;

        if verack.payload_size != 0 || verack.command_name != VERACK {
            return Err(MessageError::ExpectedVerack);
        }
        Ok(())
    }
}

/// Estructura del payload del GetHeaders Message,
/// representa todos sus campos.
pub struct GetHeadersPayload {
    pub protocol_version: u32,
    pub header_hash_count: usize,
    pub last_header_hash: [u8; 32],
    pub stopping_hash: [u8; 32],
}

impl GetHeadersPayload {
    /// Crea una nueva instancia del GetHeadersPayload.
    /// Recibe todo campo especificado en la documentacion
    /// de bitcoin para el mensaje.
    pub fn new(protocol_version: u32, last_header_hash: [u8; 32]) -> Self {
        GetHeadersPayload {
            protocol_version,
            header_hash_count: 1,
            last_header_hash,
            stopping_hash: [0; 32],
        }
    }

    /// Devuelve el GetHeadersPayload como un vector de bytes, respetando la endianness
    /// declarada en la documentacion
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut buf_message = Vec::new();
        buf_message.extend_from_slice(&(self.protocol_version).to_le_bytes());
        buf_message.extend(make_compact(self.header_hash_count));
        buf_message.extend_from_slice(&self.last_header_hash);
        buf_message.extend_from_slice(&self.stopping_hash);
        buf_message
    }

    pub fn from_bytes(stream: &mut dyn Read) -> Result<Self, MessageError> {
        let mut buf_version: [u8; 4] = [0; 4];
        stream.read_exact(&mut buf_version)?;
        let count = parse_compact(stream)?;
        let mut buf_last_header: [u8; 32] = [0; 32];
        stream.read_exact(&mut buf_last_header)?;
        let mut buf_stopping_hash: [u8; 32] = [0; 32];
        stream.read_exact(&mut buf_stopping_hash)?;

        Ok(Self {
            protocol_version: <u32>::from_le_bytes(buf_version),
            header_hash_count: count,
            last_header_hash: buf_last_header,
            stopping_hash: buf_stopping_hash,
        })
    }
}

/// Estructura del GetHeaders Message del protocolo de comunicacion bitcoin
pub struct GetHeadersMessage {
    header: MessageHeader,
    payload: GetHeadersPayload,
}

impl Message for GetHeadersMessage {
    fn as_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer.extend(&self.header.as_bytes());
        buffer.extend(&self.payload.as_bytes());
        buffer
    }
}

impl GetHeadersMessage {
    /// Crea una nueva instancia del GetHeadersMessage.
    /// Recibe todo campo especificado en la documentacion
    /// de bitcoin para el mensaje.
    pub fn new(protocol_version: u32, last_header_hash: [u8; 32]) -> Self {
        let payload = GetHeadersPayload::new(protocol_version, last_header_hash);
        let payload_bytes = payload.as_bytes();
        let message_header = MessageHeader::new("getheaders\0\0", Some(payload_bytes));
        Self {
            header: message_header,
            payload,
        }
    }
}

/// Estructura del payload del GetData Message,
/// representa todos sus campos.
pub struct GetDataPayload {
    pub count: usize,
    pub inventory_entries: Vec<(u32, [u8; 32])>,
}

impl GetDataPayload {
    /// Crea una nueva instancia del GetDataPayload.
    /// Recibe todo campo especificado en la documentacion
    /// de bitcoin para el mensaje.
    pub fn new(inventory_entries: Vec<(u32, [u8; 32])>) -> Self {
        Self {
            count: inventory_entries.len(),
            inventory_entries,
        }
    }

    /// Devuelve el GetDataPayload como un vector de bytes, respetando la endianness
    /// declarada en la documentacion
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut buf_message = Vec::new();
        buf_message.extend(make_compact(self.count));
        for inv_entry in self.inventory_entries.clone() {
            buf_message.extend_from_slice(&inv_entry.0.to_le_bytes());
            buf_message.extend_from_slice(&inv_entry.1);
        }
        buf_message
    }

    /// Parsea las entradas de los datos enviados.
    /// # Errors
    /// * al intentar leer del stream, no se encuentra la cantidad de bytes pedida. El error obtenido
    /// es un MessageError::IncompleteMessage
    pub fn parse_data_entries(stream: &mut dyn Read) -> Result<GetDataPayload, MessageError> {
        let count = parse_compact(stream)?;
        let mut inventory_entries: Vec<(u32, [u8; 32])> = Vec::new();
        for _i in 0..count {
            let mut buf_type: [u8; 4] = [0; 4];
            stream.read_exact(&mut buf_type)?;
            let mut buf_hash: [u8; 32] = [0; 32];
            stream.read_exact(&mut buf_hash)?;
            inventory_entries.push((<u32>::from_le_bytes(buf_type), buf_hash));
        }
        Ok(GetDataPayload {
            count,
            inventory_entries,
        })
    }
}

/// Estructura del GetData Message del protocolo de comunicacion bitcoin
pub struct GetDataMessage {
    header: MessageHeader,
    payload: GetDataPayload,
}

impl Message for GetDataMessage {
    fn as_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer.extend(&self.header.as_bytes());
        buffer.extend(&self.payload.as_bytes());
        buffer
    }
}

impl GetDataMessage {
    /// Crea una nueva instancia del GetDataMessage.
    /// Recibe todo campo especificado en la documentacion
    /// de bitcoin para el mensaje.
    pub fn new(inventory_entries: Vec<(u32, [u8; 32])>) -> Self {
        let payload = GetDataPayload::new(inventory_entries);
        let payload_bytes = payload.as_bytes();
        let message_header = MessageHeader::new("getdata\0\0\0\0\0", Some(payload_bytes));
        Self {
            header: message_header,
            payload,
        }
    }
}

/// Estructura del mensaje Inv de acuerdo con el protocolo bitcoin. Se comporta como un get data, ya que contiene el mismo
/// tipo de inventorio. La unica distincion es el nombre del mensaje en su header.
pub struct InvMessage {
    header: MessageHeader,
    payload: GetDataPayload,
}

impl Message for InvMessage {
    fn as_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer.extend(&self.header.as_bytes());
        buffer.extend(&self.payload.as_bytes());
        buffer
    }
}

impl InvMessage {
    /// Crea una nueva instancia del InvMessage.
    /// Recibe todo campo especificado en la documentacion
    /// de bitcoin para el mensaje.
    pub fn new(inventory_entries: Vec<(u32, [u8; 32])>) -> Self {
        let payload = GetDataPayload::new(inventory_entries);
        let payload_bytes = payload.as_bytes();
        let message_header = MessageHeader::new("inv\0\0\0\0\0\0\0\0\0", Some(payload_bytes));
        Self {
            header: message_header,
            payload,
        }
    }
}

/// Estructura del mensaje de envio de una transaccion, de acuerdo con el protocolo bitcoin
pub struct TxMessage {
    header: MessageHeader,
    payload: Vec<u8>,
}

impl TxMessage {
    /// Recibe una transaccion que desea broadcastear y devuelve el mensaje para poder realizarlo.
    pub fn new(tx: &Transaction) -> Self {
        let raw_tx = tx.as_bytes();
        let header = MessageHeader::new("tx\0\0\0\0\0\0\0\0\0\0", Some(raw_tx.clone()));
        Self {
            header,
            payload: raw_tx,
        }
    }
}

impl Message for TxMessage {
    fn as_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer.extend(&self.header.as_bytes());
        buffer.extend(&self.payload);
        buffer
    }
}

pub struct BlockMessage {
    header: MessageHeader,
    payload: Vec<u8>,
}

impl BlockMessage {
    /// Recibe una transaccion que desea broadcastear y devuelve el mensaje para poder realizarlo.
    pub fn new(block: &Block) -> Self {
        let payload = block.as_bytes();
        let header = MessageHeader::new("block\0\0\0\0\0\0\0", Some(payload.clone()));
        Self { header, payload }
    }
}

impl Message for BlockMessage {
    fn as_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer.extend(&self.header.as_bytes());
        buffer.extend(&self.payload);
        buffer
    }
}

/// Estructura del payload del Merkle Block Message,
/// representa todos sus campos.
pub struct MerkleBlockPayload {
    block_header: BlockHeader,
    transaction_count: u32,
    hash_count: usize,
    hashes: Vec<[u8; 32]>,
    flag_byte_count: usize,
    flags: Vec<u8>,
}

impl MerkleBlockPayload {
    /// Crea una nueva instancia de MerkleBlockPayload.
    /// Recibe todo campo especificado en la documentacion
    /// de bitcoin para el mensaje.
    pub fn new(
        block_header: BlockHeader,
        transaction_count: u32,
        hash_count: usize,
        hashes: Vec<[u8; 32]>,
        flag_byte_count: usize,
        flags: Vec<u8>,
    ) -> Self {
        Self {
            block_header,
            transaction_count,
            hash_count,
            hashes,
            flag_byte_count,
            flags,
        }
    }

    /// Devuelve el MerkleBlockPayload como un vector de bytes, respetando la endianness
    /// declarada en la documentacion
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut buf_message = Vec::new();
        buf_message.extend(&self.block_header.bytes);
        buf_message.extend_from_slice(&(self.transaction_count).to_le_bytes());
        buf_message.extend_from_slice(&(self.hash_count).to_le_bytes());
        for hash in self.hashes.clone() {
            buf_message.extend_from_slice(&hash);
        }
        buf_message.extend_from_slice(&(self.flag_byte_count).to_le_bytes());
        buf_message.extend_from_slice(&(self.flags));

        buf_message
    }

    /// Construye un MerkleBlockPayload a partir de la lectura de un Stream, u otro tipo de
    /// dato que implemente el trait Read
    /// # Errors
    /// * al intentar leer del stream, no se encuentra la cantidad de bytes pedida. El error obtenido
    /// es un MessageError::IncompleteMessage
    pub fn from_bytes(stream: &mut dyn Read) -> Result<Self, MessageError> {
        let mut buf_block_header = [0u8; 80];
        stream.read_exact(&mut buf_block_header)?;
        let block_header = BlockHeader::new(&buf_block_header)?;
        let mut buf_transaction_count: [u8; 4] = [0; 4];
        stream.read_exact(&mut buf_transaction_count)?;

        let hashes_size = parse_compact(stream)?;
        let mut hashes = vec![];
        for _ in 0..hashes_size {
            let mut buf_hash = [0u8; 32];
            stream.read_exact(&mut buf_hash)?;
            hashes.push(buf_hash);
        }

        let flag_byte_count = parse_compact(stream)?;
        let mut flags = vec![];
        for _ in 0..flag_byte_count {
            let mut buf_flag = [0u8; 1];
            stream.read_exact(&mut buf_flag)?;
            flags.push(<u8>::from_be_bytes(buf_flag));
        }

        Ok(MerkleBlockPayload::new(
            block_header,
            <u32>::from_le_bytes(buf_transaction_count),
            hashes_size,
            hashes,
            flag_byte_count,
            flags,
        ))
    }
}

/// Estructura del MerkleBlockMessage del protocolo de comunicacion bitcoin
pub struct MerkleBlockMessage {
    header: MessageHeader,
    payload: MerkleBlockPayload,
}

impl MerkleBlockMessage {
    /// Crea una nueva instancia de MerkleBlockMessage.
    /// Recibe todo campo especificado en la documentacion
    /// de bitcoin para el mensaje.
    pub fn new(
        block_header: BlockHeader,
        transaction_count: u32,
        hash_count: usize,
        hashes: Vec<[u8; 32]>,
        flag_byte_count: usize,
        flags: Vec<u8>,
    ) -> Self {
        let payload = MerkleBlockPayload::new(
            block_header,
            transaction_count,
            hash_count,
            hashes,
            flag_byte_count,
            flags,
        );
        let payload_bytes = payload.as_bytes();
        let header = MessageHeader::new("merkleblock\0", Some(payload_bytes));
        Self { header, payload }
    }
    /// Crea una nueva instancia de MerkleBlockMessage, leyendo todos los campos de un tipo de dato
    /// que implemente el trait read.
    /// # Errors
    /// * al intentar leer del stream, no se encuentra la cantidad de bytes pedida. El error obtenido
    /// es un MessageError::IncompleteMessage
    pub fn from_bytes(stream: &mut dyn Read) -> Result<Self, MessageError> {
        let header = MessageHeader::from_bytes(stream)?;
        let payload = MerkleBlockPayload::from_bytes(stream)?;

        Ok(Self { header, payload })
    }
}

impl Message for MerkleBlockMessage {
    fn as_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer.extend(&self.header.as_bytes());
        buffer.extend(&self.payload.as_bytes());
        buffer
    }
}

pub struct HeadersMessagePayload {
    count: usize,
    headers: Vec<BlockHeader>,
}

impl HeadersMessagePayload {
    fn new(headers: Vec<BlockHeader>) -> Self {
        Self {
            count: headers.len(),
            headers,
        }
    }

    fn as_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend(make_compact(self.count));
        for h in self.headers.iter() {
            buf.extend(h.bytes);
            buf.push(0x00);
        }
        buf
    }
}

pub struct HeadersMessage {
    header: MessageHeader,
    payload: HeadersMessagePayload,
}

impl HeadersMessage {
    pub fn new(headers: Vec<BlockHeader>) -> Self {
        let payload = HeadersMessagePayload::new(headers);
        let header = MessageHeader::new("headers\0\0\0\0\0", Some(payload.as_bytes()));
        Self { header, payload }
    }
}
impl Message for HeadersMessage {
    fn as_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer.extend(&self.header.as_bytes());
        buffer.extend(&self.payload.as_bytes());
        buffer
    }
}

pub struct AddrMessage {
    header: MessageHeader,
    payload: Vec<Address>,
}

impl AddrMessage {
    pub fn new(addresses: Vec<Address>) -> Self {
        let header = MessageHeader::new(
            "addr\0\0\0\0\0\0\0\0",
            Some(Address::payload_as_bytes(&addresses)),
        );
        Self {
            header,
            payload: addresses,
        }
    }
}

impl Message for AddrMessage {
    fn as_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer.extend(&self.header.as_bytes());
        buffer.extend(Address::payload_as_bytes(&self.payload));
        buffer
    }
}

#[derive(Clone)]
pub struct Address {
    time: u32,
    services: u64,
    ip_address: [u8; 16],
    port: u16,
}

impl Address {
    pub fn new() -> Result<Self, MessageError> {
        let ip_address = local_ip_address::local_ip()?;
        let ip_bytes = match ip_address {
            IpAddr::V6(ipv6) => u128::from(ipv6).to_be_bytes(),
            IpAddr::V4(ipv4) => u128::from(ipv4.to_ipv6_compatible()).to_be_bytes(),
        };
        Ok(Self {
            time: Utc::now().timestamp() as u32,
            services: 0,
            ip_address: ip_bytes,
            port: TESTNET_PORT,
        })
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend(self.time.to_le_bytes());
        buf.extend(self.services.to_le_bytes());
        buf.extend(self.ip_address);
        buf.extend(self.port.to_be_bytes());
        buf
    }

    pub fn payload_as_bytes(addresses: &Vec<Address>) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend(make_compact(addresses.len()));
        for addr in addresses {
            buf.extend(addr.as_bytes());
        }
        buf
    }
}
