use crate::{
    interface::{
        graphics::{init_window, ToGraphic},
        gui_handler::ProgramState,
    },
    user::wallet::Wallet,
    utils::errors::{InterfaceError, WalletError},
};
use glib;
use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, Mutex},
};

fn create_wallet_from_strings(
    map: &mut HashMap<String, Arc<Mutex<Wallet>>>,
    name: String,
    privkey: String,
    addr: (IpAddr, u16),
    handler_sender: glib::Sender<ToGraphic>,
) -> Result<Arc<Mutex<Wallet>>, WalletError> {
    let new_wallet;
    if privkey.is_empty() {
        new_wallet = Wallet::new(addr, handler_sender)?;
        map.insert(name, new_wallet.clone());
    } else {
        new_wallet = Wallet::new_from(&privkey, addr, handler_sender)?;
        map.insert(name, new_wallet.clone());
    }

    Ok(new_wallet)
}
type SafeWallet = Arc<Mutex<Wallet>>;
pub fn login_wallet(
    addr: (IpAddr, u16),
    handler_sender: glib::Sender<ToGraphic>,
) -> Result<(HashMap<String, SafeWallet>, SafeWallet), InterfaceError> {
    let log_users = match init_window() {
        Ok(log_users) => log_users,
        Err(_) => return Err(InterfaceError::CouldntCreateInterface),
    };

    let mut wallets_handler: HashMap<String, Arc<Mutex<Wallet>>> = HashMap::new();

    let wallets_lock = match log_users.lock() {
        Ok(w) => w,
        Err(_) => return Err(InterfaceError::CouldntCreateInterface),
    };

    if wallets_lock.is_empty() {
        return Err(InterfaceError::CouldntCreateInterface);
    }

    let selected_wallet = create_wallet_from_strings(
        &mut wallets_handler,
        wallets_lock[0].0.clone(),
        wallets_lock[0].1.clone(),
        addr,
        handler_sender.clone(),
    )?;
    for (name, privkey) in wallets_lock.iter().skip(1) {
        create_wallet_from_strings(
            &mut wallets_handler,
            name.clone(),
            privkey.clone(),
            addr,
            handler_sender.clone(),
        )?;
    }
    Ok((wallets_handler, selected_wallet))
}

pub fn set_initial_screen(program: &mut ProgramState) -> Result<(), InterfaceError> {
    for (i, name) in program.wallets.keys().enumerate() {
        if i == 0
            && program
                .sender
                .send(ToGraphic::ChangedWallet(name.clone()))
                .is_err()
        {
            return Err(InterfaceError::LostCommunicationToGUI);
        }
        if program
            .sender
            .send(ToGraphic::WalletAdded(name.clone()))
            .is_err()
        {
            return Err(InterfaceError::LostCommunicationToGUI);
        }
    }
    if program.sender.send(ToGraphic::InitWallet).is_err() {
        return Err(InterfaceError::LostCommunicationToGUI);
    }

    Ok(())
}
