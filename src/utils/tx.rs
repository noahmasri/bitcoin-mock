use bitcoin_hashes::{sha256d, Hash};
use secp256k1::{ecdsa::Signature, PublicKey};
use std::io::Read;

use crate::{
    utils::compact_size::{make_compact, parse_compact, parse_compact_and_witness},
    utils::errors::MessageError,
};

const MAX_SCRIPT_BYTES: usize = 10000;
/// Estructura de una transaccion,
/// representa todos sus campos especificados en la documentacion.
#[derive(Debug, PartialEq, Clone)]
pub struct Transaction {
    pub version: i32,
    pub tx_in_count: usize,
    pub tx_in: Vec<Input>,
    pub tx_out_count: usize,
    pub tx_out: Vec<Output>,
    pub witness_list: Option<Vec<Vec<u8>>>,
    pub lock_time: u32,
}

impl Transaction {
    /// Realiza la traduccion a bytes de una transaccion
    #[must_use]
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut buf_message = Vec::new();
        buf_message.extend_from_slice(&(self.version).to_le_bytes());
        buf_message.extend(make_compact(self.tx_in_count));
        for input in &self.tx_in {
            buf_message.extend(input.as_bytes());
        }
        buf_message.extend(make_compact(self.tx_out_count));
        for output in &self.tx_out {
            buf_message.extend(output.as_bytes());
        }
        buf_message.extend_from_slice(&(self.lock_time).to_le_bytes());
        buf_message
    }

    /// Devuelve el hash de una transaccion, en formato array. Esto es, el Sha256 doble de todos los bytes que la componen
    #[must_use]
    pub fn hash(&self) -> [u8; 32] {
        sha256d::Hash::hash(self.as_bytes().as_slice()).to_byte_array()
    }

    /// Genera una transaccion en base a lo leido de un stream.
    /// `# Errors` :
    /// * MessageError::IncompleteMessage` : si se genera un error en el `read_exact` del stream
    pub fn parse_transaction(stream: &mut dyn Read) -> Result<Transaction, MessageError> {
        let mut buf_version: [u8; 4] = [0; 4];
        stream.read_exact(&mut buf_version)?;
        let version = <i32>::from_le_bytes(buf_version);
        let (has_witness, tx_in_count) = parse_compact_and_witness(stream)?;
        let mut tx_in: Vec<Input> = Vec::new();
        for _ in 0..tx_in_count {
            let input = Input::parse_input(stream)?;
            tx_in.push(input);
        }

        let tx_out_count = parse_compact(stream)?;
        let mut tx_out: Vec<Output> = Vec::new();
        for _ in 0..tx_out_count {
            let output = Output::parse_output(stream)?;
            tx_out.push(output);
        }
        let mut witnesses: Option<Vec<Vec<u8>>> = None;
        if has_witness {
            witnesses = Some(parse_witnesses(stream)?);
        }
        let mut buf_lock_time: [u8; 4] = [0; 4];
        stream.read_exact(&mut buf_lock_time)?;
        let lock_time = <u32>::from_le_bytes(buf_lock_time);

        Ok(Transaction {
            version,
            tx_in_count,
            tx_in,
            tx_out_count,
            tx_out,
            witness_list: witnesses,
            lock_time,
        })
    }

    /// Crea una transaccion con inputs y outputs dados.Los inputs no estan firmados.
    #[must_use]
    pub fn new_unsigned_from_inout(inputs: Vec<Input>, outputs: Vec<Output>) -> Self {
        Transaction {
            version: 1,
            tx_in_count: inputs.len(),
            tx_in: inputs,
            tx_out_count: outputs.len(),
            tx_out: outputs,
            witness_list: None,
            lock_time: 0,
        }
    }

    /// Modifica la transaccion para incluir en los inputs el script de la firma, conformado por el signature y el hash del public key
    /// de quien la creo.
    pub fn sign(&mut self, signature: Signature, pubkey: PublicKey) {
        let mut sign = signature.serialize_der().to_vec();
        sign.extend(&make_compact(1));
        let mut sigscript: Vec<u8> = Vec::new();

        let sig_bytes = make_compact(sign.len());
        sigscript.extend(sig_bytes);
        sigscript.extend(sign);

        let serialized_pk = pubkey.serialize_uncompressed().to_vec();
        sigscript.extend(make_compact(serialized_pk.len()));
        sigscript.extend(serialized_pk);

        for input in self.tx_in.iter_mut() {
            input.script_bytes = sigscript.len();
            input.signature_script = sigscript.clone();
        }
    }

    #[must_use]
    pub fn signature_hash(&self) -> Vec<u8> {
        let mut tx_bytes = self.as_bytes();
        let sighashall: u32 = 1;
        tx_bytes.extend(sighashall.to_le_bytes());
        tx_bytes
    }
}

/// Estructura de un input de una transaccion,
/// representa todos sus campos especificados
/// en la documentación.
#[derive(Debug, PartialEq, Clone)]
pub struct Input {
    pub previous_outpoint: Outpoint,
    pub script_bytes: usize, //cs
    pub signature_script: Vec<u8>,
    pub sequence: u32,
}

impl Input {
    /// Devuelve el Input como un vector de bytes, respetando la endianness
    /// declarada en la documentacion.
    #[must_use]
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut buf_message = Vec::new();
        buf_message.extend(&(self.previous_outpoint).as_bytes());
        buf_message.extend(make_compact(self.script_bytes));
        buf_message.extend(&self.signature_script);
        buf_message.extend_from_slice(&(self.sequence).to_le_bytes());
        buf_message
    }

    fn parse_input(stream: &mut dyn Read) -> Result<Input, MessageError> {
        let previous_outpoint = Outpoint::parse_outpoint(stream)?;
        let script_bytes = parse_compact(stream)?;
        if script_bytes > MAX_SCRIPT_BYTES {
            return Err(MessageError::InvalidTransaction);
        }

        let mut signature_script: Vec<u8> = Vec::new();
        for _ in 0..script_bytes {
            let mut buf_sig_script: [u8; 1] = [0];
            stream.read_exact(&mut buf_sig_script)?;
            let script_byte = <u8>::from_le_bytes(buf_sig_script);
            signature_script.push(script_byte);
        }

        let mut buf_seq: [u8; 4] = [0; 4];
        stream.read_exact(&mut buf_seq)?;

        let sequence = <u32>::from_le_bytes(buf_seq);
        Ok(Input {
            previous_outpoint,
            script_bytes,
            signature_script,
            sequence,
        })
    }
}

/// Estructura del outpoint vinculada a un único input.
#[derive(Debug, PartialEq, Clone, Copy)]
pub struct Outpoint {
    pub hash: [u8; 32],
    pub index: u32,
}
impl Outpoint {
    /// Devuelve el Outpoint como un vector de bytes, respetando la endianness
    /// declarada en la documentacion
    #[must_use]
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut buf_message = Vec::new();
        buf_message.extend_from_slice(&self.hash);
        buf_message.extend_from_slice(&(self.index).to_le_bytes());
        buf_message
    }

    /// Devuelve una instancia de la estructura Outpoint a partir del stream
    /// pasado por parámetro.
    ///
    /// # Errors
    /// * al intentar leer del stream, no se encuentra la cantidad de bytes pedida. El error obtenido
    /// es un `MessageError::IncompleteMessage`
    pub fn parse_outpoint(stream: &mut dyn Read) -> Result<Outpoint, MessageError> {
        let mut hash: [u8; 32] = [0; 32];
        stream.read_exact(&mut hash)?;
        let mut buf_index: [u8; 4] = [0; 4];
        stream.read_exact(&mut buf_index)?;
        let index = <u32>::from_le_bytes(buf_index);

        Ok(Outpoint { hash, index })
    }

    /// Devuelve true si el outpoint está vinculado a la coinbase,
    /// falso si no.
    #[must_use]
    pub fn is_coinbase_outpoint(&self) -> bool {
        let coinbase_hash: [u8; 32] = [0; 32];
        let index: [u8; 4] = [0xff, 0xff, 0xff, 0xff];
        let index_num = <u32>::from_le_bytes(index);

        index_num == self.index && coinbase_hash == self.hash
    }
}

/// Estructura de un output de una transaccion,
/// representa todos sus campos especificados
/// en la documentación.
#[derive(Clone, Debug, PartialEq)]
pub struct Output {
    pub value: i64,
    pub pk_script_bytes: usize, //cs
    pub pk_script: Vec<u8>,
}

impl Output {
    /// Devuelve el Output como un vector de bytes, respetando la endianness
    /// declarada en la documentacion
    #[must_use]
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut buf_message: Vec<u8> = Vec::new();
        buf_message.extend_from_slice(&(self.value).to_le_bytes());
        buf_message.extend_from_slice(&(make_compact(self.pk_script_bytes)));
        buf_message.extend(&self.pk_script);
        buf_message
    }

    fn parse_output(stream: &mut dyn Read) -> Result<Output, MessageError> {
        let mut buf_value: [u8; 8] = [0; 8];
        stream.read_exact(&mut buf_value)?;
        let value: i64 = <i64>::from_le_bytes(buf_value);
        let pk_script_bytes = parse_compact(stream)?;
        if pk_script_bytes > MAX_SCRIPT_BYTES {
            return Err(MessageError::InvalidTransaction);
        }

        let mut pk_script: Vec<u8> = Vec::new();
        for _ in 0..pk_script_bytes {
            let mut buf_pk_script: [u8; 1] = [0];
            stream.read_exact(&mut buf_pk_script)?;
            let script_byte = <u8>::from_le_bytes(buf_pk_script);
            pk_script.push(script_byte);
        }

        Ok(Output {
            value,
            pk_script_bytes,
            pk_script,
        })
    }
}

/// Funcion utilizada para parsear el testigo de una transaccion, en base a las especificaciones
/// de la documentacion de Bitcoin.
/// # Errors
/// * al intentar leer del stream, no se encuentra la cantidad de bytes pedida. El error obtenido
/// es un `MessageError::IncompleteMessage`
fn parse_witnesses(stream: &mut dyn Read) -> Result<Vec<Vec<u8>>, MessageError> {
    let mut wdcs: Vec<Vec<u8>> = Vec::new();
    let count = parse_compact(stream)?;
    for _ in 0..count {
        let wdclen = parse_compact(stream)?;
        let mut wdc: Vec<u8> = Vec::new();

        for _ in 0..wdclen {
            let mut buf: [u8; 1] = [0];
            stream.read_exact(&mut buf)?;
            let byte = <u8>::from_le_bytes(buf);
            wdc.push(byte);
        }
        wdcs.push(wdc);
    }
    Ok(wdcs)
}

/// Estructura de la transaccción coinbase de un bloque,
/// representa todos sus campos especificados en la documentación.
#[derive(Debug, PartialEq, Clone)]
pub struct Coinbase {
    pub version: i32,
    pub tx_in_count: usize, //cs
    pub tx_in: CoinbaseInput,
    pub tx_out_count: usize, //cs
    pub tx_out: Vec<Output>,
    pub lock_time: u32, // Unix epoch time o block number
}

impl Coinbase {
    /// Devuelve el Coinbase como un vector de bytes, respetando la endianness
    /// declarada en la documentacion.
    #[must_use]
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut buf_message = Vec::new();
        buf_message.extend_from_slice(&(self.version).to_le_bytes());
        buf_message.extend(make_compact(self.tx_in_count));
        buf_message.extend(self.tx_in.as_bytes());
        buf_message.extend(make_compact(self.tx_out_count));
        for output in &self.tx_out {
            buf_message.extend(&output.as_bytes());
        }
        buf_message.extend_from_slice(&(self.lock_time).to_le_bytes());
        buf_message
    }

    /// Devuelve el hash del coinbase
    #[must_use]
    pub fn hash(&self) -> [u8; 32] {
        sha256d::Hash::hash(self.as_bytes().as_slice()).to_byte_array()
    }

    /// Parsea los bytes recibidos por el stream pasado por parametro
    /// a un struct de Coin Base.
    ///
    /// # Errors
    /// * al intentar leer del stream, no se encuentra la cantidad de bytes pedida. El error obtenido
    /// es un `MessageError::IncompleteMessage`
    pub fn parse_coinbase_transaction(stream: &mut dyn Read) -> Result<Self, MessageError> {
        let mut buf_version: [u8; 4] = [0; 4];
        stream.read_exact(&mut buf_version)?;
        let version = <i32>::from_le_bytes(buf_version);
        let (has_witness, tx_in_count) = parse_compact_and_witness(stream)?;
        if tx_in_count != 1 {
            return Err(MessageError::MissingCoinbaseTx);
        }
        let coinbase_input = CoinbaseInput::parse_input(stream)?;
        let tx_out_count = parse_compact(stream)?;
        let mut tx_out: Vec<Output> = Vec::new();
        for _ in 0..tx_out_count {
            let output = Output::parse_output(stream)?;
            tx_out.push(output);
        }
        if has_witness {
            parse_witnesses(stream)?;
        }
        let mut buf_lock_time: [u8; 4] = [0; 4];
        stream.read_exact(&mut buf_lock_time)?;
        let lock_time = <u32>::from_le_bytes(buf_lock_time);
        Ok(Coinbase {
            version,
            tx_in_count,
            tx_in: coinbase_input,
            tx_out_count,
            tx_out,

            lock_time,
        })
    }
}

/// Estructura del unico input de una coinbase,
/// representa todos sus campos especificados en la documentacion.
#[derive(Debug, PartialEq, Clone)]
pub struct CoinbaseInput {
    pub previous_outpoint: Outpoint,
    pub script_bytes: usize,
    pub height: u32,
    coinbase_script: Vec<u8>,
    sequence: u32,
}

impl CoinbaseInput {
    /// Devuelve el `CoinbaseInput` como un vector de bytes, respetando la endianness
    /// declarada en la documentacion.
    #[must_use]
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut buf_message = Vec::new();
        buf_message.extend_from_slice(&(self.previous_outpoint).as_bytes());
        buf_message.extend(make_compact(self.script_bytes));
        let height_extra: [u8; 1] = [0x03];
        buf_message.extend_from_slice(&height_extra);
        let height: [u8; 4] = (self.height).to_le_bytes();
        buf_message.extend_from_slice(&height[..3]);
        buf_message.extend(&self.coinbase_script);
        buf_message.extend_from_slice(&(self.sequence).to_le_bytes());
        buf_message
    }

    fn parse_height(stream: &mut dyn Read) -> Result<u32, MessageError> {
        let mut height_bytes: [u8; 1] = [0; 1];
        stream.read_exact(&mut height_bytes)?;
        let mut height_aux = Vec::new();
        let mut height_buf: [u8; 3] = [0; 3];
        stream.read_exact(&mut height_buf)?;
        let extra_byte_height: [u8; 1] = [0; 1];
        height_aux.extend_from_slice(&height_buf);
        height_aux.extend_from_slice(&extra_byte_height);
        Ok(<u32>::from_le_bytes(height_aux[..4].try_into()?))
    }

    fn parse_input(stream: &mut dyn Read) -> Result<CoinbaseInput, MessageError> {
        let previous_outpoint = Outpoint::parse_outpoint(stream)?;
        if !previous_outpoint.is_coinbase_outpoint() {
            return Err(MessageError::MissingCoinbaseTx);
        }
        let script_bytes = parse_compact(stream)?;
        if script_bytes > MAX_SCRIPT_BYTES {
            return Err(MessageError::InvalidTransaction);
        }
        let height = Self::parse_height(stream)?;
        let mut signature_script: Vec<u8> = Vec::new();
        for _ in 0..script_bytes - 4 {
            let mut buf_sig_script: [u8; 1] = [0];
            stream.read_exact(&mut buf_sig_script)?;
            let script_byte = <u8>::from_le_bytes(buf_sig_script);
            signature_script.push(script_byte);
        }

        let mut buf_seq: [u8; 4] = [0; 4];
        stream.read_exact(&mut buf_seq)?;
        let sequence = <u32>::from_le_bytes(buf_seq);

        Ok(CoinbaseInput {
            previous_outpoint,
            script_bytes,
            height,
            coinbase_script: signature_script,
            sequence,
        })
    }

    /// Devuelve el hash del `CoinbaseInput` (en formato arreglo).
    #[must_use]
    pub fn hash(&self) -> [u8; 32] {
        let mut hash = sha256d::Hash::hash(self.as_bytes().as_slice()).to_byte_array();
        hash.reverse();
        hash
    }
}

#[cfg(test)]
mod test {
    use std::io::BufReader;

    use super::*;
    use crate::utils::errors::DownloadError;

    #[test]
    fn parsing_coinbase_transaction_and_getting_its_hash_gives_expected_hash() {
        //https://tbtc.bitaps.com/7366111f2d3b32b22e1a529c4a70b4618058e09441c40bfbef410a15f18dad76
        let correct_hash = "7366111f2d3b32b22e1a529c4a70b4618058e09441c40bfbef410a15f18dad76";
        let hexa_hash_bytes = hex::decode(correct_hash).expect("Failed to decode hex string");
        let mut hash_bytes = hexa_hash_bytes.as_slice().to_owned();
        hash_bytes.reverse();
        let raw_tx = "010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff1b03a9242504b70f6864003000000e35eb0000084d617261636f726500000000020000000000000000266a24aa21a9ed11b8417f13519962f137f9eb1e06a9ac31b938046884f868c8ddf65de9724a1b4cc12500000000001976a914e359f695c80fc9f7192446cdc94aafa007fae2e688ac0120000000000000000000000000000000000000000000000000000000000000000000000000";
        let tx_bytes = hex::decode(raw_tx).expect("Failed to decode hex string");
        let mut reader = BufReader::new(tx_bytes.as_slice());
        let tx: Coinbase = Coinbase::parse_coinbase_transaction(&mut reader).unwrap();
        let alleged_tx_hash = tx.hash();
        assert_eq!(hash_bytes, alleged_tx_hash);
    }

    #[test]
    fn parsing_transactions_and_getting_its_hash_gives_expected_hash_with_witness() {
        //https://tbtc.bitaps.com/raw/transaction/4ee3102ac6e2822babcedeb4f7f8b6b5a9cc508308e282575bed118c6d919a68
        let correct_hash = "4ee3102ac6e2822babcedeb4f7f8b6b5a9cc508308e282575bed118c6d919a68";
        let hexa_hash_bytes = hex::decode(correct_hash).expect("Failed to decode hex string");
        let mut hash_bytes = hexa_hash_bytes.as_slice().to_owned();
        hash_bytes.reverse();
        let raw_tx = "0200000000010156cf24df7b49955e41f2da35185563fc8e028a43d021bedc7c4ef9d5fde46b690100000000feffffff02df6f1100000000001600141f0c248af4d3f0c65c234ec814681a4f71cb2864801537fe01000000160014448e944572b6124a3430c9048d9cab10c1999ec40247304402200a19d248f960de0056f7d20c1d913b005a84018755c8f29fee63bbce980f179c0220377f145fc0f6576b1cad6882551934e10c03f675f7640a8b95b2baf49a9fa0ea0121022eaac72f7554b36b9812cda106cac353569f4709fe1005e18d3199961cfb372a70252500";
        let tx_bytes = hex::decode(raw_tx).expect("Failed to decode hex string");

        let mut reader = BufReader::new(tx_bytes.as_slice());
        let tx: Transaction = Transaction::parse_transaction(&mut reader).unwrap();
        let alleged_tx_hash = tx.hash();
        assert_eq!(hash_bytes, alleged_tx_hash);
    }

    #[test]
    fn parsing_transactions_and_getting_its_hash_gives_expected_hash_without_witness() {
        //link: https://tbtc.bitaps.com/4b8a7a93e4683347e55503573314fd093a44bbd299022fa42d222b58096d6eb5
        let correct_hash = "4b8a7a93e4683347e55503573314fd093a44bbd299022fa42d222b58096d6eb5";
        let hexa_hash_bytes = hex::decode(correct_hash).expect("Failed to decode hex string");
        let mut hash_bytes = hexa_hash_bytes.as_slice().to_owned();
        hash_bytes.reverse();
        let raw_tx = "0100000001d916c479340f7a1b247637882e3be6182bb52f07026c03e0420a2e26e8c84f87030000006a47304402206a1e454d62adfa9db40ea618fbb8c7b96a0a7f3a1d503a43afee2b563037398c0220711c1a9a24559af6c369af4a28630d48076328b3e3f0643b551df1d35ccf0e420121037435c194e9b01b3d7f7a2802d6684a3af68d05bbf4ec8f17021980d777691f1dfdffffff040000000000000000536a4c5054325bfcdea51957ada12a6fade1b5a6b734717b422ec64d5eb3d62f8330ea4c2d95746995df07cc62aecbf2aef22061afb22b5968c920f79814fa3cecf25c9c67493c00252564000b002524f600144c10270000000000001976a914000000000000000000000000000000000000000088ac10270000000000001976a914000000000000000000000000000000000000000088acdfe19501000000001976a914ba27f99e007c7f605a8305e318c1abde3cd220ac88ac00000000";
        let tx_bytes = hex::decode(raw_tx).expect("Failed to decode hex string");

        let mut reader = BufReader::new(tx_bytes.as_slice());
        let tx: Transaction = Transaction::parse_transaction(&mut reader).unwrap();
        let alleged_tx_hash = tx.hash();
        assert_eq!(hash_bytes, alleged_tx_hash);
    }

    #[test]
    fn coinbase_height_is_parsed_appropriately() -> Result<(), DownloadError> {
        let mut content: Vec<u8> = Vec::new();
        let height: u32 = 328014;
        let start = [0x03];
        content.extend_from_slice(&start);
        content.extend_from_slice(&height.to_le_bytes());
        let mut reader = BufReader::new(content.as_slice());
        let parsed = CoinbaseInput::parse_height(&mut reader)?;
        assert_eq!(height, parsed);
        Ok(())
    }

    #[test]
    fn parsing_and_unparsing_returns_same_raw_tx() -> Result<(), DownloadError> {
        let raw = "0200000001525e8870a8b2be4ed02b4d26c498ecf32971e1f8b206b86006093d3e6c06bf7b010000006a47304402204591df098680e03e196eabbfff09a1c4f686ab6cf5c8b441f7ce0539d653ff760220249371cceaa034abbc0233cddfbab3d6e702ca52ddcac27c7a29b6304a3d6d20012103d68a77b95c35e960fc08057b13e543901f781a334642453b140f9d619bec952dffffffff02740e00000000000017a9143b413c7427a65d79a9355aa4c78d6fd8ed7877b08766f80c00000000001976a9141a0674423dd19b6f72c360a18c13384f39eb0c3488ac00000000";
        let hexa_raw = hex::decode(raw).unwrap();
        let mut reader = BufReader::new(hexa_raw.as_slice());
        let tx = Transaction::parse_transaction(&mut reader)?;
        let unparsed = tx.as_bytes();
        assert_eq!(unparsed, hexa_raw);
        Ok(())
    }
}
