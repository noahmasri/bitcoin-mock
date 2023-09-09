use crate::interface::graphics::{FromGraphic, ToGraphic};
use crate::user::wallet::{BroadcastedTx, Wallet};
use crate::utils::config::Config;
use crate::utils::errors::InterfaceError;
use bitcoin_hashes::{sha256d, Hash};
use glib::Sender;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::{mpsc, Arc, Mutex};

pub struct ProgramState {
    pub wallets: HashMap<String, Arc<Mutex<Wallet>>>,
    pub selected: Arc<Mutex<Wallet>>,
    pub config: Config,
    pub sender: Sender<ToGraphic>,
    pub receiver: mpsc::Receiver<FromGraphic>,
}

impl ProgramState {
    pub fn new(
        wallets: HashMap<String, Arc<Mutex<Wallet>>>,
        selected: Arc<Mutex<Wallet>>,
        config: Config,
        sender: Sender<ToGraphic>,
        receiver: mpsc::Receiver<FromGraphic>,
    ) -> Self {
        ProgramState {
            wallets,
            selected,
            config,
            sender,
            receiver,
        }
    }

    pub fn hear_the_gui(&mut self) -> Result<(), InterfaceError> {
        loop {
            let msg = self.receiver.recv()?;
            match msg {
                FromGraphic::TransactionInformation(txid) => self.get_tx_info(txid),
                FromGraphic::EndGraphic => {
                    self.end_node_connections()?;
                    break;
                }
                FromGraphic::AddWallet(name, privkey) => self.create_new_wallet(name, &privkey),
                FromGraphic::GetBalance => self.get_balance(),
                FromGraphic::ChangeWallet(name) => self.select_wallet(name),
                FromGraphic::GetTransactions => self.get_transactions(),
                FromGraphic::TransactionToSend(address, amount) => {
                    self.send_transaction(&address, &amount)
                }
                FromGraphic::GetProofOfInclusion(txid, block_height) => {
                    self.ask_for_proof(txid, block_height)
                }
                FromGraphic::GetMyTransactions => self.get_sent_transactions(),
                FromGraphic::GetMyAddr => self.get_my_add(),
            }?;
        }
        Ok(())
    }

    fn end_node_connections(&self) -> Result<(), InterfaceError> {
        for wallet in self.wallets.values() {
            let locked_wallet = wallet.lock()?;
            locked_wallet.end_connection_to_node()?;
        }
        Ok(())
    }
    fn get_my_add(&self) -> Result<(), InterfaceError> {
        if let Ok(locked_wallet) = self.selected.lock() {
            let addr = locked_wallet.get_address()?;
            drop(locked_wallet);
            self.sender.send(ToGraphic::MyAddress(
                String::from_utf8_lossy(&addr).to_string(),
            ))?;
        } else {
            self.sender.send(ToGraphic::Error(
                "Error en la generacion del balance".to_string(),
            ))?;
        }
        Ok(())
    }
    fn get_balance(&self) -> Result<(), InterfaceError> {
        if let Ok(locked_wallet) = self.selected.lock() {
            let balance = locked_wallet.get_balance();
            drop(locked_wallet);
            self.sender.send(ToGraphic::Balance(balance))?;
        } else {
            self.sender.send(ToGraphic::Error(
                "Error en la generacion del balance".to_string(),
            ))?;
        }
        Ok(())
    }

    fn parse_height_and_txid(
        &mut self,
        txid: String,
        block_height: String,
    ) -> Result<Option<([u8; 32], u32)>, InterfaceError> {
        let txid_u8: [u8; 32] = match sha256d::Hash::from_str(&txid) {
            Ok(id) => id.to_byte_array(),
            Err(_) => {
                self.sender
                    .send(ToGraphic::Error("Txid ingresado invalido".to_string()))?;
                return Ok(None);
            }
        };

        let height: u32 = match block_height.parse() {
            Ok(height) => height,
            Err(_) => {
                self.sender
                    .send(ToGraphic::Error("Altura proveida invalida".to_string()))?;
                return Ok(None);
            }
        };
        Ok(Some((txid_u8, height)))
    }

    fn ask_for_proof(&mut self, txid: String, block_height: String) -> Result<(), InterfaceError> {
        let (txid_u8, height) = match self.parse_height_and_txid(txid, block_height)? {
            Some(parsed) => parsed,
            None => return Ok(()),
        };

        let wallet = match self.selected.lock() {
            Ok(locked_wallet) => locked_wallet,
            Err(_) => {
                self.sender
                    .send(ToGraphic::Error("Fatal error ".to_string()))?;
                self.sender.send(ToGraphic::EndInterface)?;
                return Ok(());
            }
        };
        wallet.request_poi(txid_u8, height)?;
        Ok(())
    }

    fn select_wallet(&mut self, name: String) -> Result<(), InterfaceError> {
        if let Some(new_wallet) = self.wallets.get(&name) {
            self.selected = new_wallet.clone();
            self.sender.send(ToGraphic::ChangedWallet(name))?;
        } else {
            self.sender.send(ToGraphic::Error(
                "Error al obtener la billetera".to_string(),
            ))?;
        }
        Ok(())
    }

    fn create_new_wallet(&mut self, name: String, privkey: &str) -> Result<(), InterfaceError> {
        let address = self.config.get_address();
        if privkey.is_empty() {
            if let Ok(new_wallet) = Wallet::new(address, self.sender.clone()) {
                self.wallets.insert(name.clone(), new_wallet);
                self.sender.send(ToGraphic::WalletAdded(name))?;
            } else {
                self.sender.send(ToGraphic::Error(
                    "Error en la creacion de la billetera".to_string(),
                ))?;
                return Ok(());
            }
        } else if let Ok(new_wallet) = Wallet::new_from(privkey, address, self.sender.clone()) {
            self.wallets.insert(name.clone(), new_wallet);
            self.sender.send(ToGraphic::WalletAdded(name))?;
        } else {
            self.sender.send(ToGraphic::Error(
                "Error en la creacion de la billetera".to_string(),
            ))?;
        }
        Ok(())
    }
    //manda las txs para el grid y llama a la de txids
    fn get_transactions(&mut self) -> Result<(), InterfaceError> {
        if let Ok(locked_wallet) = self.selected.lock() {
            self.sender
                .send(ToGraphic::Transactions(locked_wallet.get_txs()))?;
            drop(locked_wallet);
        } else {
            self.sender.send(ToGraphic::Error(
                "Error al obtener la transaccion".to_string(),
            ))?;
            return Ok(());
        }
        Ok(())
    }

    fn address_from_string_to_array(
        &self,
        address: &str,
    ) -> Result<Option<[u8; 34]>, InterfaceError> {
        let mut addr: [u8; 34] = [0; 34];
        if address.len() != 34 {
            self.sender.send(ToGraphic::Error(
                "La direccion ingresada no es valida".to_string(),
            ))?;
            return Ok(None);
        }

        for (i, letra) in address.chars().enumerate() {
            addr[i] = letra as u8;
        }

        Ok(Some(addr))
    }

    // crea una transaccion
    fn send_transaction(&mut self, address: &str, amount: &str) -> Result<(), InterfaceError> {
        let Some(addr_array) = self.address_from_string_to_array(address)? else { return Ok(()) };
        let result = str::replace(amount, ",", ".");
        let amount_btc: f64 = match result.parse::<f64>() {
            Ok(number) => number,
            Err(_) => return Err(InterfaceError::ErrorWhileParsing),
        };
        if amount_btc <= 0.0 {
            self.sender.send(ToGraphic::Error(
                "No se puede crear transaccion con valor 0".to_string(),
            ))?;
            return Ok(());
        }
        let mut wallet_locked = self.selected.lock()?;
        let (txid, amount) = match wallet_locked.create_transaction(vec![(amount_btc, addr_array)])
        {
            Ok(id) => id,
            Err(e) => {
                self.sender.send(ToGraphic::Error(format!(
                    "No se pudo crear la transaccion. Error:{:?}",
                    e
                )))?;
                return Ok(());
            }
        };
        drop(wallet_locked);
        let amount_spent = 0.0 - Wallet::satoshi_to_bitcoins(amount);
        let txid = sha256d::Hash::from_byte_array(txid).to_string();
        self.sender
            .send(ToGraphic::TransactionSent(txid, amount_spent.to_string()))?;
        Ok(())
    }

    // devuelve los transation ids de las transacciones enviadas
    fn get_sent_transactions(&self) -> Result<(), InterfaceError> {
        let locked_wallet = self.selected.lock()?;
        let mut txids_str = Vec::new();
        let txids = locked_wallet.get_my_broadcasted_tx_ids();
        drop(locked_wallet);
        for txid in txids {
            txids_str.push(sha256d::Hash::from_byte_array(txid).to_string());
        }
        self.sender.send(ToGraphic::MyTransactions(txids_str))?;
        Ok(())
    }

    fn format_wallet_info_and_send(
        &self,
        tx_info: &BroadcastedTx,
        txid: String,
    ) -> Result<(), InterfaceError> {
        let state = match tx_info.confirmed {
            true => String::from("Confirmed"),
            false => String::from("Unconfirmed"),
        };

        let height = format!("{}", tx_info.height);
        let mut raw = format!(
            "version: {}\n number of inputs: {}\n",
            tx_info.tx.version, tx_info.tx.tx_in_count
        );
        for input in tx_info.tx.tx_in.iter() {
            let outid = hex::encode(input.previous_outpoint.hash);
            let sig_script = hex::encode(input.signature_script.clone());
            raw += format!("Outpoint TXID: {}\n Outpoint index number: {}\n  Bytes in sig. script: {}\n Signature script: {}\n Sequence Number: {}\n \n",outid,input.previous_outpoint.index,input.script_bytes,sig_script,input.sequence).as_str();
        }
        raw += format!("Number of outputs: {}\n", tx_info.tx.tx_out_count).as_str();
        for output in tx_info.tx.tx_out.iter() {
            let btc = Wallet::satoshi_to_bitcoins(output.value);
            let pk_script = hex::encode(output.pk_script.clone());
            raw += format!(
                "Satoshis: {} ({} BTC)\n Bytes in pubkey script: {} \nScript PubKey {}\n \n",
                output.value, btc, output.pk_script_bytes, pk_script
            )
            .as_str();
        }
        raw += format!("Locked: {}\n", tx_info.tx.lock_time).as_str();
        self.sender.send(ToGraphic::TransactionInformation(
            txid,
            Wallet::satoshi_to_bitcoins(tx_info.amount_spent).to_string(),
            state,
            height,
            raw,
        ))?;
        Ok(())
    }
    //devuelve de la transaccion informacion en el siguiente formato: txid, amount,state,height,raw tx format
    fn get_tx_info(&self, txid: String) -> Result<(), InterfaceError> {
        let tx_id = sha256d::Hash::from_str(&txid)?;
        let locked_wallet = self.selected.lock()?;
        if let Some(tx_info) = locked_wallet.get_tx_info(tx_id.to_byte_array()) {
            self.format_wallet_info_and_send(tx_info, txid)?;
        } else {
            drop(locked_wallet);
            self.sender.send(ToGraphic::Error(String::from(
                "No se pudo pedir la transaccion",
            )))?;
        }
        Ok(())
    }
}
