const OP_DUP: [u8; 1] = [0x76];
const OP_HASH160: [u8; 1] = [0xa9];
const OP_PUSH_BYTES_20: [u8; 1] = [0x14];
const OP_EQUALVERIFY: [u8; 1] = [0x88];
const OP_CHECKSIG: [u8; 1] = [0xac];
const AVERAGE_LEN: i64 = 300;
const FEE: i64 = AVERAGE_LEN * 3;

use crate::interface::graphics::ToGraphic;
use crate::server::utxos::UtxoInfo;
use crate::utils::errors::WalletError;
use crate::utils::tx::{Input, Outpoint, Output, Transaction};
use crate::utils::wallet_messages::{
    BlockInclusion, IncomingTx, POIAnswer, POIRequest, Payload, UtxoResponse, WalletId,
    WalletMessage, WalletMessageHeader,
};
use bitcoin_hashes::{ripemd160, sha256, sha256d, Hash};
use glib;
use rand::rngs::OsRng;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, TcpStream};
use std::sync::{Arc, Mutex};

#[derive(Debug)]
pub struct BroadcastedTx {
    pub tx: Transaction,
    pub amount_spent: i64,
    pub confirmed: bool,
    pub height: u32,
}

#[derive(Debug)]
pub struct Wallet {
    pub pubkey: PublicKey,
    privkey: SecretKey,
    // transactions sent by wallet
    broadcasted_tx: HashMap<[u8; 32], BroadcastedTx>,
    node: TcpStream,
    utxos: Vec<UtxoInfo>,
}

impl Wallet {
    fn new_with_generated_keys(
        addr: (IpAddr, u16),
        pubkey: PublicKey,
        privkey: SecretKey,
        gui_channel: glib::Sender<ToGraphic>,
    ) -> Result<Arc<Mutex<Wallet>>, WalletError> {
        let pubkey_hash = Self::pubkey_hash(&pubkey);
        let node = Self::connect_to_node(pubkey_hash, addr)?;
        let wallet = Self {
            pubkey,
            privkey,
            broadcasted_tx: HashMap::new(),
            node,
            utxos: Vec::new(),
        };

        let mutex_wallet = Arc::new(Mutex::new(wallet));
        Self::background_hearing(mutex_wallet.clone(), gui_channel);
        Ok(mutex_wallet)
    }

    // Genera un nuevo set de claves publicas y privadas. Devuelve un wallet.
    // Inicia el background hearing, que quedara escuchando al nodo.
    pub fn new(
        addr: (IpAddr, u16),
        gui_channel: glib::Sender<ToGraphic>,
    ) -> Result<Arc<Mutex<Wallet>>, WalletError> {
        let secp: Secp256k1<secp256k1::All> = Secp256k1::new();
        let (secret_key, public_key) = secp.generate_keypair(&mut OsRng);
        Self::new_with_generated_keys(addr, public_key, secret_key, gui_channel)
    }

    /// Crea una wallet con una private key preexistente, dada en Wallet Import Format
    pub fn new_from(
        my_priv_key: &str,
        addr: (IpAddr, u16),
        gui_channel: glib::Sender<ToGraphic>,
    ) -> Result<Arc<Mutex<Self>>, WalletError> {
        let decoded = Wallet::decode_private_key(String::from(my_priv_key))?;
        let priv_key: SecretKey = SecretKey::from_slice(&decoded)?;
        let secp: Secp256k1<secp256k1::All> = Secp256k1::new();
        let public_key = PublicKey::from_secret_key(&secp, &priv_key);
        Self::new_with_generated_keys(addr, public_key, priv_key, gui_channel)
    }

    fn connect_to_node(
        pubkey_hash: [u8; 20],
        addr: (IpAddr, u16),
    ) -> Result<TcpStream, WalletError> {
        let mut socket = TcpStream::connect(addr)?;
        let connect_msg = WalletMessage::new(Payload::ConnectToNode(WalletId::new(pubkey_hash)));
        socket.write_all(&connect_msg.as_bytes())?;
        let ask_utxos = WalletMessage::new(Payload::GetUtxo(WalletId::new(pubkey_hash)));
        socket.write_all(&ask_utxos.as_bytes())?;
        let node = socket.try_clone()?;
        Ok(node)
    }

    /// Manda un mensaje al nodo para que olvide su clave y no le notifique nada mas
    /// # Errors:
    /// * Si no se puede conectar con el nodo, o si no puede clonar el stream WalletError::CouldntConnectToNode
    pub fn end_connection_to_node(&self) -> Result<(), WalletError> {
        let pubkey_hash = Self::pubkey_hash(&self.pubkey);
        let mut node_clone = self.node.try_clone()?;
        node_clone.write_all(
            &WalletMessage::new(Payload::EndConnection(WalletId::new(pubkey_hash))).as_bytes(),
        )?;
        Ok(())
    }

    fn handle_node_messages(
        command_name: &str,
        wallet: Arc<Mutex<Wallet>>,
        stream: &mut dyn Read,
        gui_channel: glib::Sender<ToGraphic>,
    ) -> Result<(), WalletError> {
        match command_name {
            "sendutxo\0\0\0\0" => {
                if let Ok(new) = UtxoResponse::from_reader(stream) {
                    if let Ok(mut lockof_wallet) = wallet.lock() {
                        lockof_wallet.utxos = new.utxos;
                        drop(lockof_wallet);
                    }
                };
            }
            "blockinclude" => {
                if let Ok(block_incoming) = BlockInclusion::from_reader(stream) {
                    if let Ok(mut lock_wallet) = wallet.lock() {
                        lock_wallet.handle_new_block_and_announce(block_incoming, gui_channel)?;
                    }
                }
            }
            "incomingtx\0\0" => {
                if let Ok(new_tx) = IncomingTx::from_reader(stream) {
                    if let Ok(lock_wallet) = wallet.lock() {
                        lock_wallet.send_incoming_tx_to_gui(new_tx, gui_channel)?;
                    }
                }
            }
            "poianswer\0\0\0" => {
                Self::answer_poi_request(stream, gui_channel)?;
            }

            _ => {}
        }
        Ok(())
    }

    fn background_hearing(wallet: Arc<Mutex<Wallet>>, gui_channel: glib::Sender<ToGraphic>) {
        std::thread::spawn(move || {
            let mut buf = [0; 1];
            if let Ok(locked_wallet) = wallet.lock() {
                if let Ok(mut stream) = locked_wallet.node.try_clone() {
                    drop(locked_wallet);
                    while let Ok(a) = stream.peek(&mut buf) {
                        if a == 0 {
                            continue;
                        }
                        if let Ok(header) = WalletMessageHeader::from_reader(&mut stream) {
                            let message_command_name = header.message_name();
                            if Self::handle_node_messages(
                                message_command_name.as_str(),
                                wallet.clone(),
                                &mut stream,
                                gui_channel.clone(),
                            )
                            .is_err()
                            {
                                break;
                            }
                        }
                    }
                }
            }
        });
    }

    fn handle_new_block_and_announce(
        &mut self,
        block_incoming: BlockInclusion,
        gui_channel: glib::Sender<ToGraphic>,
    ) -> Result<(), WalletError> {
        if let Some(mut tx) = self.broadcasted_tx.remove(&block_incoming.txid) {
            if !tx.confirmed {
                tx.confirmed = true;
                tx.height = block_incoming.block_height;
                //avisar interfaz porque era una que hicimos nosotras que se acaba de confirmar
                self.send_block_inclusion_to_gui(block_incoming, gui_channel)?;
                self.broadcasted_tx.insert(block_incoming.txid, tx);
            }
        } else {
            //si no estaba en el hash es porque es una hacia nosotros => avisar que nos hicieron una nueva
            self.send_block_inclusion_of_tx_to_self(block_incoming, gui_channel)?;
        }
        self.request_update_utxos()?;
        Ok(())
    }

    fn request_update_utxos(&self) -> Result<(), WalletError> {
        let msg = WalletMessage::new(Payload::GetUtxo(WalletId::new(Self::pubkey_hash(
            &self.pubkey,
        ))));

        let mut stream = self.node.try_clone()?;
        stream.write_all(&msg.as_bytes())?;

        Ok(())
    }

    /// Manda un mensaje al nodo para pedirle la proof of inclusion de una transaccion txid en un bloque de altura height
    /// # Errors:
    /// * Si no se puede conectar con el nodo, o si no puede clonar el stream WalletError::CouldntConnectToNode
    pub fn request_poi(&self, txid: [u8; 32], height: u32) -> Result<(), WalletError> {
        let msg = WalletMessage::new(Payload::PoiRequest(POIRequest::new(txid, height)));
        let mut stream = self.node.try_clone()?;
        stream.write_all(&msg.as_bytes())?;
        Ok(())
    }

    // Envia a la interfaz un mensaje avisando que llego una transaccion dirigida hacia el
    // (esta incluido en los outputs) pero que esta aun no ha sido confirmada
    fn send_incoming_tx_to_gui(
        &self,
        tx: IncomingTx,
        gui_channel: glib::Sender<ToGraphic>,
    ) -> Result<(), WalletError> {
        let my_address = self.get_address()?;
        let address_readable = hex::encode(my_address);
        let txid_readable = hex::encode(tx.txid);
        let mut announcement = String::from("");
        announcement += &format!("Wallet address: {} \nreceived new output in transaction of: \nhash {} \nindex : \n{} for amount: {:?}\n and is yet to be confirmed", address_readable, txid_readable, tx.index, tx.value);
        gui_channel.send(ToGraphic::TxAnnouncement(announcement))?;
        Ok(())
    }

    // Envia a la interfaz un mensaje avisando que llego un bloque que contiene
    // una transaccion que este habia creado
    fn send_block_inclusion_to_gui(
        &self,
        block: BlockInclusion,
        gui_channel: glib::Sender<ToGraphic>,
    ) -> Result<(), WalletError> {
        let my_address = self.get_address()?;
        let address_readable = hex::encode(my_address);
        let txid_readable = hex::encode(block.txid);
        let mut announcement = String::from("");
        announcement += &format!("Wallet address: {} \nreceived confirmation for transaction \n{} \nin block of height: {:?}", address_readable, txid_readable, block.block_height);
        gui_channel.send(ToGraphic::BlockAnnouncement(
            announcement,
            format!("{:?}", txid_readable),
        ))?;
        Ok(())
    }

    // Envia a la interfaz un mensaje avisando que llego un bloque que contiene
    // una transaccion que genera para este un nuevo utxo
    fn send_block_inclusion_of_tx_to_self(
        &self,
        block: BlockInclusion,
        gui_channel: glib::Sender<ToGraphic>,
    ) -> Result<(), WalletError> {
        let my_address = self.get_address()?;
        let address_readable = hex::encode(my_address);
        let txid_readable = hex::encode(block.txid);
        let mut announcement = String::from("");
        announcement += &format!(
            "Wallet address: \n {} \nreceived a new transaction \n{:?} \nin block of height: {:?}",
            address_readable, txid_readable, block.block_height
        );
        gui_channel.send(ToGraphic::BlockNewAnnouncement(announcement))?;
        Ok(())
    }

    fn send_poi_to_gui(
        inclusion: POIAnswer,
        gui_channel: glib::Sender<ToGraphic>,
    ) -> Result<(), WalletError> {
        let mut string = String::from("");
        if inclusion.count == 0 {
            gui_channel.send(ToGraphic::NotProofOfInclusion)?;
        }
        let txid_readable = hex::encode(inclusion.txid);
        string += &format!("txid: {}\n", txid_readable);
        for i in 0..inclusion.count {
            let left = hex::encode(inclusion.path[i].0);
            let right = hex::encode(inclusion.path[i].1);
            string += &format!("\nH( {} | {} )\n", left, right);
        }

        gui_channel.send(ToGraphic::ProofOfInclusion(string.clone()))?;
        Ok(())
    }

    // responde al pedido de la interfaz de realizar la proof of inclusion.
    // si el primer byte es 0, es que pudo realizar la prueba, aunque puede que no se haya demostrado
    // si el primer byte es 1, el nodo no contaba con el bloque de altura en donde se queria buscar
    fn answer_poi_request(
        stream: &mut dyn Read,
        gui_channel: glib::Sender<ToGraphic>,
    ) -> Result<(), WalletError> {
        let mut error_byte: [u8; 1] = [0; 1];
        stream.read_exact(&mut error_byte)?;
        if error_byte == [0] {
            if let Ok(proof) = POIAnswer::from_reader(stream) {
                Self::send_poi_to_gui(proof, gui_channel)?;
            }
        } else if error_byte == [1] {
            gui_channel.send(ToGraphic::BlockNotAvailable)?;
        }
        Ok(())
    }

    /// Devuelve toda la informacion sobre una transaccion que esta misma wallet creo y
    /// pidio al nodo que envie por la red
    pub fn get_tx_info(&self, txid: [u8; 32]) -> Option<&BroadcastedTx> {
        self.broadcasted_tx.get(&txid)
    }

    /// Devuelve un vector con los hashes de todas las transacciones que esta wallet envio
    pub fn get_my_broadcasted_tx_ids(&self) -> Vec<[u8; 32]> {
        let mut txids = Vec::new();
        for (tx_id, _) in self.broadcasted_tx.iter() {
            txids.push(*tx_id);
        }
        txids
    }

    fn round_decimal_value(num: f64) -> f64 {
        let entero: i64 = (num * 1e8).round() as i64;
        entero as f64 / 1e8
    }

    /// Devuelve un vector de arrays de 3 strings, donde la primera posicion de este array
    /// es el estado de la transaccion, la segunda es el valor de esta, negativo si es una
    /// transaccion hecha por la wallet, positivo si es un unspent transaction output
    pub fn get_txs(&self) -> Vec<[String; 3]> {
        let mut txs_info: Vec<[String; 3]> = Vec::new();
        for (tx_id, tx_info) in self.broadcasted_tx.iter() {
            let state = match tx_info.confirmed {
                true => String::from("Confirmed"),
                false => String::from("Unconfirmed"),
            };

            let value =
                Self::round_decimal_value(0.0 - Self::satoshi_to_bitcoins(tx_info.amount_spent));
            let info: [String; 3] = [state, hex::encode(tx_id), value.to_string()];
            txs_info.push(info);
        }

        for utxo in self.utxos.iter() {
            let info = [
                String::from("Confirmed"),
                sha256d::Hash::from_byte_array(utxo.txid).to_string(),
                Self::round_decimal_value(Self::satoshi_to_bitcoins(utxo.amount)).to_string(),
            ];
            txs_info.push(info);
        }
        txs_info
    }

    fn decode_private_key(privkey: String) -> Result<Vec<u8>, WalletError> {
        let decoded = bs58::decode(privkey).into_vec()?;
        if decoded.len() > 5 {
            let cut = decoded[1..decoded.len() - 4].to_vec();
            return Ok(cut);
        }
        Err(WalletError::CouldntGenerateKey)
    }

    fn pubkey_hash(pubkey: &PublicKey) -> [u8; 20] {
        ripemd160::Hash::hash(&sha256::Hash::hash(&pubkey.serialize_uncompressed()).to_byte_array())
            .to_byte_array()
    }

    fn get_pk_script_bytes(hash: [u8; 20]) -> Vec<u8> {
        let mut pk_script_bytes: Vec<u8> = Vec::new();
        pk_script_bytes.extend_from_slice(&OP_DUP);
        pk_script_bytes.extend_from_slice(&OP_HASH160);
        pk_script_bytes.extend_from_slice(&OP_PUSH_BYTES_20);
        pk_script_bytes.extend(hash);

        pk_script_bytes.extend_from_slice(&OP_EQUALVERIFY);
        pk_script_bytes.extend_from_slice(&OP_CHECKSIG);

        pk_script_bytes
    }

    /// Suma los valores de todos los unspent outputs de la wallet
    pub fn get_balance(&self) -> f64 {
        let balance: i64 = self.utxos.iter().map(|entry| entry.amount).sum();
        Self::round_decimal_value(Self::satoshi_to_bitcoins(balance))
    }

    /// Devuelve la private key en wallet import format para poder hacer persistencia
    pub fn get_encoded_private_key(&self) -> String {
        let secret_bytes = self.privkey.secret_bytes();
        let mut extended: Vec<u8> = vec![0xef];
        extended.extend(&secret_bytes);

        let sha256d_extended = sha256d::Hash::hash(&extended);

        let checksum = &sha256d_extended[..4];
        extended.extend(checksum);

        let address = bs58::encode(extended);
        address.into_string()
    }

    pub fn get_address(&self) -> Result<[u8; 34], WalletError> {
        let pubkey_hash = Self::pubkey_hash(&self.pubkey);
        let mut extended = vec![0x6f];
        extended.extend(&pubkey_hash);

        let sha256_extended = sha256::Hash::hash(&extended);
        let sha256d_extended = sha256::Hash::hash(&sha256_extended.to_byte_array());

        let checksum = &sha256d_extended[..4];
        extended.extend(checksum);
        let mut addr_buf = [0; 34];
        bs58::encode(extended).onto(&mut addr_buf[..])?;
        Ok(addr_buf)
    }

    fn search_outpoints(
        amount: i64,
        my_utxos: Vec<UtxoInfo>,
    ) -> Result<(Vec<UtxoInfo>, i64), WalletError> {
        let mut counter = 0;
        let amount_w_estimated_fee = amount + FEE; // leaving 3s/vbyte fee approximately
        let mut to_use: Vec<UtxoInfo> = Vec::new();
        for utxo in my_utxos {
            if utxo.amount >= amount_w_estimated_fee {
                let rest = utxo.amount - amount; //if rest is too much, send some to self
                return Ok((vec![utxo], rest));
            }

            counter += utxo.amount;
            to_use.push(utxo);

            if counter >= amount_w_estimated_fee {
                let rest = counter - amount;
                return Ok((to_use, rest));
            }
        }
        Err(WalletError::NotEnoughBalance)
    }

    fn get_pk_from_addr(addr: [u8; 34]) -> Result<Vec<u8>, WalletError> {
        let decoded = bs58::decode(&addr).into_vec()?;
        if decoded.len() > 5 {
            let cut = decoded[1..decoded.len() - 4].to_vec();
            let pk = Wallet::get_pk_script_bytes(cut.try_into()?);
            return Ok(pk);
        }
        Err(WalletError::CouldntGeneratePKScript)
    }

    fn build_unsigned_inputs(&self, to_spend: Vec<UtxoInfo>) -> Result<Vec<Input>, WalletError> {
        let my_pk_script = Wallet::get_pk_script_bytes(Self::pubkey_hash(&self.pubkey));
        let mut inputs: Vec<Input> = Vec::new();
        for outpoint in to_spend.iter() {
            let inp = Input {
                previous_outpoint: Outpoint {
                    hash: outpoint.txid,
                    index: outpoint.index,
                },
                script_bytes: my_pk_script.len(),
                signature_script: my_pk_script.clone(),
                sequence: 0xffffffff,
            };
            inputs.push(inp);
        }
        Ok(inputs)
    }

    fn build_outputs(
        &self,
        recv_addresses: Vec<(i64, [u8; 34])>,
        rest: i64,
    ) -> Result<Vec<Output>, WalletError> {
        let mut outputs = Vec::new();
        for addr in recv_addresses {
            let pk_script = Wallet::get_pk_from_addr(addr.1)?;
            let output = Output {
                value: addr.0,
                pk_script_bytes: pk_script.len(),
                pk_script,
            };
            outputs.push(output);
        }
        let output_to_self = self.build_rest_output(rest)?;
        outputs.push(output_to_self);
        Ok(outputs)
    }

    fn build_rest_output(&self, amount: i64) -> Result<Output, WalletError> {
        let my_pks = Wallet::get_pk_from_addr(self.get_address()?)?;
        Ok(Output {
            value: amount - FEE,
            pk_script_bytes: my_pks.len(),
            pk_script: my_pks,
        })
    }

    /// Convierte un valor en satoshis a uno en bitcoins
    pub fn satoshi_to_bitcoins(satoshi_amount: i64) -> f64 {
        Self::round_decimal_value(satoshi_amount as f64 * 0.00000001)
    }

    /// Convierte un valor en bitcoins a uno en satoshis
    fn bitcoins_to_satoshi(btc_amount: f64) -> i64 {
        (btc_amount / 0.00000001).floor() as i64
    }

    fn change_outputs_to_satoshi_vals(
        recv_addresses: Vec<(f64, [u8; 34])>,
    ) -> Vec<(i64, [u8; 34])> {
        let mut recv = Vec::new();
        for (val, addr) in recv_addresses {
            recv.push((Self::bitcoins_to_satoshi(val), addr));
        }
        recv
    }

    /// Dado un vector de tuplas de dinero a transferir y direcciones a las que enviarlo,
    /// genera una transaccion.
    /// # Errors
    /// * No cuenta con el dinero suficiente para realizar la transaccion. El error obtenido es
    /// WalletError::NotEnoughBalance
    /// * No se puede obtener la direccion de la propia wallet. El error es WalletError::UnexpectedErrorGeneratingAddress.
    /// * No se puede obtener el pk-script. El error obtenido es WalletError::CouldntGeneratePKScript.
    /// * No se puede construir el outpoint a la hora de crear los inputs. El error obtenido es WalletError::CouldntGenerateInputOutpoint
    /// * No se puede crear el mensaje a firmar. El error obtenido es WalletError::CouldntBuildMessage
    pub fn create_transaction(
        &mut self,
        recv_addresses: Vec<(f64, [u8; 34])>,
    ) -> Result<([u8; 32], i64), WalletError> {
        let new_recv = Self::change_outputs_to_satoshi_vals(recv_addresses);
        let amount_to_transfer = new_recv.iter().map(|&(val, _)| val).sum();
        let (outputs_to_spend, rest) =
            Wallet::search_outpoints(amount_to_transfer, self.utxos.clone())?;

        let mut unsigned_tx = Transaction::new_unsigned_from_inout(
            self.build_unsigned_inputs(outputs_to_spend)?,
            self.build_outputs(new_recv, rest)?,
        );

        let signature = self
            .privkey
            .sign_ecdsa(secp256k1::Message::from_hashed_data::<sha256d::Hash>(
                &unsigned_tx.signature_hash(),
            ));

        unsigned_tx.sign(signature, self.pubkey);
        let hash = unsigned_tx.clone().hash();
        let amount_spent = amount_to_transfer + rest;

        self.broadcasted_tx.insert(
            hash,
            BroadcastedTx {
                tx: unsigned_tx.clone(),
                amount_spent,
                confirmed: false,
                height: 0,
            },
        );

        let send_tx = WalletMessage::new(Payload::CreateTx(unsigned_tx));
        let mut socket = self.node.try_clone()?;
        socket.write_all(&send_tx.as_bytes())?;

        Ok((hash, amount_spent))
    }

    /// Devuelve la transaccion en caso de que pertenezca a la wallet,
    /// caso contrario devuelve un None.
    pub fn is_my_unconfirmed_tx(&self, tx_hash: [u8; 32]) -> Option<&Transaction> {
        if let Some(tx_info) = self.broadcasted_tx.get(&tx_hash) {
            if !tx_info.confirmed {
                return Some(&tx_info.tx);
            }
        }
        None
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn can_convert_from_bitcoins_to_satoshis() {
        let btc1 = 0.00001;
        let satoshis1 = Wallet::bitcoins_to_satoshi(btc1);

        let btc2 = 3.0;
        let satoshis2 = Wallet::bitcoins_to_satoshi(btc2);

        let btc3 = 0.00000004;
        let satoshis3 = Wallet::bitcoins_to_satoshi(btc3);

        assert_eq!(1000, satoshis1);
        assert_eq!(300000000, satoshis2);
        assert_eq!(4, satoshis3);
    }

    #[test]
    fn can_convert_from_satoshis_to_bitcoins() {
        let sat1 = 12042;
        let bitcoin1 = Wallet::satoshi_to_bitcoins(sat1);

        let sat2 = 1;
        let bitcoin2 = Wallet::satoshi_to_bitcoins(sat2);

        let sat3 = 12929939;
        let bitcoin3 = Wallet::satoshi_to_bitcoins(sat3);

        assert_eq!(0.00012042, bitcoin1);
        assert_eq!(0.00000001, bitcoin2);
        assert_eq!(0.12929939, bitcoin3);
    }
}
