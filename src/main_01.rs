use std::{env, sync::mpsc, thread};
use tp_bitcoins::{
    interface::{
        graphics::{graphic_interface, FromGraphic, ToGraphic},
        gui_handler::ProgramState,
    },
    user::login::{login_wallet, set_initial_screen},
    utils::{config::Config, errors::InterfaceError},
};

fn main() -> Result<(), InterfaceError> {
    let arguments: Vec<String> = env::args().collect();

    if arguments.len() < 2 {
        println!("ERROR: Missing configuration file");
        return Ok(());
    }

    let config = match Config::from_filepath(&arguments[1]) {
        Ok(c) => c,
        Err(e) => {
            println!("There was an error ({e:?}) reading configuration file, default will be used",);
            Config::default()
        }
    };

    let addr = (config.ip_address, config.port);
    let (handler_sender, gui_rx) = glib::MainContext::channel::<ToGraphic>(glib::PRIORITY_DEFAULT);
    let (gui_sender, handler_rx) = mpsc::channel::<FromGraphic>();

    let (wallets_handler, selected_wallet) = login_wallet(addr, handler_sender.clone())?;

    let handler_thread = thread::spawn(move || {
        let mut program = ProgramState::new(
            wallets_handler,
            selected_wallet,
            config,
            handler_sender,
            handler_rx,
        );
        if set_initial_screen(&mut program).is_err() {
            return;
        }
        if program.hear_the_gui().is_err() {
            println!("ERROR: Se perdio la comunicacion con la interfaz.");
        }
    });

    graphic_interface(gui_rx, gui_sender)?;

    if handler_thread.join().is_err() {
        return Err(InterfaceError::CouldSendMessage);
    }
    Ok(())
}
