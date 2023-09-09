use std::{
    env,
    sync::{mpsc, Arc, Mutex},
};

use tp_bitcoins::{
    server::logfile::LogFile,
    server::networklistener::NetworkListener,
    server::{logfile::write_in_log, node::Node},
    utils::config::Config,
    utils::errors::NodeError,
};

fn main() -> Result<(), NodeError> {
    let arguments: Vec<String> = env::args().collect();

    if arguments.len() < 2 {
        println!("ERROR: Missing configuration file");
        return Ok(());
    }

    let config = match Config::from_filepath(&arguments[1]) {
        Ok(c) => c,
        Err(e) => {
            println!("There was an error ({e:?}) reading configuration file, default will be used");
            Config::default()
        }
    };

    let (sender_log, receiver_log) = mpsc::channel::<String>();
    let log = LogFile::new(config.log_file_addr.clone(), receiver_log);
    let thread_log = std::thread::spawn(move || {
        if let Ok(mut l) = log {
            l.flush_messages();
        }
    });
    let addr = (config.ip_address, config.port);
    let node = Node::new(config, 18333, Some(sender_log.clone()))?;

    let mutex_node = Arc::new(Mutex::new(node));
    let (network_listener, rx_data) =
        NetworkListener::new(mutex_node.clone(), Some(sender_log.clone()))?;

    let mutex_network = Arc::new(Mutex::new(network_listener));
    let network_clone = mutex_network.clone();

    let thread_listener =
        std::thread::spawn(move || NetworkListener::receive_data(network_clone, rx_data));
    let sender_node_clone = sender_log.clone();
    let mutex_node_clone = mutex_node.clone();
    let mutex_network_clone = mutex_network.clone();
    let thread_server = std::thread::spawn(move || {
        Node::listen_for_peers(
            mutex_node_clone,
            Some(sender_node_clone),
            mutex_network_clone,
        )
    });

    if let Err(e) =
        Node::listen_for_clients(mutex_node, addr, mutex_network, Some(sender_log.clone()))
    {
        write_in_log(
            vec![format!(
                "There was an error ({e:?}) when connecting to wallets"
            )],
            Some(sender_log),
        );
    }

    if thread_listener.join().is_err() {
        return Err(NodeError::UnableToJoinHandles);
    }
    if thread_log.join().is_err() {
        return Err(NodeError::UnableToJoinHandles);
    }
    if thread_server.join().is_err() {
        return Err(NodeError::UnableToJoinHandles);
    }
    Ok(())
}
