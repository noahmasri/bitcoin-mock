//! Este modulo tiene toda la interfaz necesaria para el manejo de un log file de nodo
//! el cual registra todos los mensajes que este recibe, tanto de sus wallets como de los
//! peers de la red
use std::io::Write;
use std::{
    fs::{File, OpenOptions},
    sync::mpsc::{Receiver, Sender},
};

use chrono::{Local, Utc};

/// Guardamos lo necesario para escribir en el log file
pub struct LogFile {
    receiver: Receiver<String>,
    file: File,
}

///Interfaz para que se escriba en el log file
pub fn write_in_log(messages: Vec<String>, sender: Option<Sender<String>>) {
    let fecha = Utc::now().format("%d-%m-%y").to_string();
    let hora = Local::now().format("%H:%M:%S").to_string();
    if let Some(log_file) = sender {
        for val in messages {
            let mut w_date = format!("{fecha} {hora} ");
            w_date += &val;
            if log_file.send(w_date).is_err() {
                break;
            }
        }
    }
}

impl LogFile {
    /// Intenta crear un log file que escriba lo recibido por el receiver dado en un archivo ubicado en el path dado
    pub fn new(addr: String, receiver: Receiver<String>) -> Result<LogFile, std::io::Error> {
        match OpenOptions::new()
            .append(true)
            .create(true)
            .read(true)
            .open(addr)
        {
            Ok(log_file) => Ok(Self {
                receiver,
                file: log_file,
            }),
            Err(e) => {
                drop(receiver);
                Err(e)
            }
        }
    }

    /// permite al final de la ejecuccion escribir en el log file lo enviado por el programa
    pub fn flush_messages(&mut self) {
        while let Ok(rx) = self.receiver.recv() {
            if writeln!(self.file, "{rx}").is_err() {
                println!("Couldnt write in logfile");
                break;
            }
        }
    }
}
