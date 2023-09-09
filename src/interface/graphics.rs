use crate::utils::errors::InterfaceError;
use gtk::prelude::{Cast, *};
use std::sync::mpsc;
use std::sync::Arc;
use std::sync::Mutex;

pub enum ToGraphic {
    InitWallet,
    Error(String),
    Balance(f64),
    WalletAdded(String),
    ChangedWallet(String),
    Transactions(Vec<[String; 3]>),    // PARA VENTANA TRANSACTION
    BlockAnnouncement(String, String), // LLEGA BLOQUE CON TX
    BlockNewAnnouncement(String),
    TxAnnouncement(String), // LLEGA TX NO CONFIRMADA
    ProofOfInclusion(String),
    NotProofOfInclusion,
    BlockNotAvailable,
    TransactionInformation(String, String, String, String, String), //para la ListBox
    TransactionSent(String, String),
    MyTransactions(Vec<String>),
    EndInterface,
    MyAddress(String),
}

pub enum FromGraphic {
    EndGraphic,
    ChangeWallet(String),
    GetBalance,
    AddWallet(String, String),
    GetTransactions,
    GetMyTransactions,
    TransactionToSend(String, String),
    GetProofOfInclusion(String, String),
    TransactionInformation(String),
    GetMyAddr,
}
type SafeString = Arc<Mutex<Vec<(String, String)>>>;

fn try_open_gtk_objects<T: gtk::prelude::IsA<gtk::glib::Object>>(
    builder: &gtk::Builder,
    id: &str,
) -> Result<T, InterfaceError> {
    match builder.object(id) {
        Some(object) => Ok(object),
        None => Err(InterfaceError::CouldntCreateInterface),
    }
}

///Genera una ventana inicial, la que te pide que ingreses una wallet para poder continuar con el programa
/// # Errors
/// * si hay problemas con la carga de alguno de los elementos de la interfaz
pub fn init_window() -> Result<SafeString, InterfaceError> {
    if gtk::init().is_err() {
        return Err(InterfaceError::CouldntCreateInterface);
    }
    let builder = gtk::Builder::from_string(include_str!("init_window.glade"));

    let init_window: gtk::Window = try_open_gtk_objects(&builder, "init_window")?;
    let close: gtk::Button = try_open_gtk_objects(&builder, "close")?;
    close.set_sensitive(false);

    let wallet_privkey: gtk::Entry = try_open_gtk_objects(&builder, "wallet_privkey")?;
    let wallet_name_to_add: gtk::Entry = try_open_gtk_objects(&builder, "wallet_name1")?;

    let wallet_name_to_create: gtk::Entry = try_open_gtk_objects(&builder, "wallet_name2")?;
    let add: gtk::Button = try_open_gtk_objects(&builder, "add")?;

    let create: gtk::Button = try_open_gtk_objects(&builder, "create")?;

    let close_copy = close.clone();
    let vec: Arc<Mutex<Vec<(String, String)>>> = Arc::new(Mutex::new(Vec::new()));
    let vec_copy = vec.clone();
    add.connect_clicked(move |_| {
        if wallet_privkey.text().len() == 51 {
            if let Ok(mut locked_vec) = vec_copy.lock() {
                locked_vec.push((
                    wallet_name_to_add.text().to_string(),
                    wallet_privkey.text().to_string(),
                ));
                close_copy.set_sensitive(true);
                drop(locked_vec);
            };
        } else {
            error_window("private key invalida");
        };

        wallet_privkey.delete_text(0, wallet_privkey.text().len() as i32);
        wallet_name_to_add.delete_text(0, wallet_name_to_add.text().len() as i32);
    });

    let close_copy = close.clone();
    let vec_copy = vec.clone();
    create.connect_clicked(move |_| {
        if let Ok(mut locked_vec) = vec_copy.lock() {
            locked_vec.push((wallet_name_to_create.text().to_string(), String::new()));
            close_copy.set_sensitive(true);
            drop(locked_vec);
        };
        wallet_name_to_create.delete_text(0, wallet_name_to_create.text().len() as i32);
    });

    init_window.show_all();

    close.connect_clicked(move |_| {
        init_window.hide();
        gtk::main_quit();
    });

    gtk::main();

    Ok(vec)
}

fn transaction_info(
    txid: String,
    amount: String,
    state: String,
    block: String,
    raw: String,
) -> Result<(), InterfaceError> {
    let builder = gtk::Builder::from_string(include_str!("tx_window.glade"));
    let tx_window: gtk::Window = try_open_gtk_objects(&builder, "tx_window")?;
    let txid_label: gtk::Label = try_open_gtk_objects(&builder, "txid_label")?;
    txid_label.set_text(&txid);
    let amount_label: gtk::Label = try_open_gtk_objects(&builder, "amount_label")?;
    amount_label.set_text(&amount);

    let block_label: gtk::Label = try_open_gtk_objects(&builder, "block_label")?;
    block_label.set_text(&block);

    let state_label: gtk::Label = try_open_gtk_objects(&builder, "state_label")?;
    state_label.set_text(&state);
    let raw_label: gtk::Label = try_open_gtk_objects(&builder, "raw_label")?;
    raw_label.set_text(&raw);
    tx_window.show_all();
    Ok(())
}

fn error_window(mesaje: &str) {
    let builder = gtk::Builder::from_string(include_str!("error_window.glade"));
    let e_label: gtk::Label = match builder.object("e_label") {
        Some(e_label) => e_label,
        None => return,
    };
    e_label.set_text(mesaje);
    if let Some(e_window) = builder.object::<gtk::Window>("e_window") {
        e_window.show_all();
    };
}

fn setear_announcements(
    label1: &mut gtk::Label,
    label2: &mut gtk::Label,
    label3: &mut gtk::Label,
    label4: &mut gtk::Label,
    name: &str,
) {
    label1.set_text(name);
    label2.set_text(name);
    label3.set_text(name);
    label4.set_text(name);
}

fn transaction_to_send(
    address_to_pay: &gtk::Entry,
    amount: &gtk::SpinButton,
    sender: mpsc::Sender<FromGraphic>,
) -> Result<(), InterfaceError> {
    let address_to_pay_str = address_to_pay.text();
    if address_to_pay_str.is_empty() || amount.text().is_empty() {
        error_window("Info requerida no enviada");
        return Ok(());
    }

    sender.send(FromGraphic::TransactionToSend(
        address_to_pay.text().to_string(),
        amount.text().to_string(),
    ))?;
    Ok(())
}

fn handle_incoming(
    msg: ToGraphic,
    label_with_amount: &mut gtk::Label,
    grids: (&mut gtk::Grid, &mut gtk::Grid),
    sender: &mut mpsc::Sender<FromGraphic>,
    (wallet_list, listbox): (&mut gtk::ComboBoxText, &mut gtk::ListBox),
    announcements: (gtk::Label, gtk::Label, gtk::Label, gtk::Label),
    (my_add_buff, my_add): (&mut gtk::TextBuffer, &mut gtk::TextView),
) -> Result<(), InterfaceError> {
    let (txs_grid, recent_txs) = grids;
    let (mut announcement_0, mut announcement_1, mut announcement_2, mut announcement_3) =
        announcements;

    match msg {
        ToGraphic::InitWallet => {
            wallet_list.set_active(Some(0));
            Ok(())
        }
        ToGraphic::Balance(balance) => {
            label_with_amount.set_text(&balance.to_string());
            Ok(())
        }
        ToGraphic::ChangedWallet(_name) => update_window(sender, my_add),
        ToGraphic::Error(string) => {
            error_window(&string);
            Ok(())
        }
        ToGraphic::Transactions(txs) => set_all_txs(&mut txs_grid.clone(), recent_txs, txs),
        ToGraphic::MyTransactions(txs) => {
            clean_list(listbox);
            for txid in txs {
                // let tx = gtk::TextView::new();
                // let buff = gtk::TextBuffer::new(None::<&gtk::TextTagTable>);
                // buff.set_text(&txid);
                // tx.set_editable(false);
                let tx = gtk::Label::new(Some(&txid));
                let row_copy: gtk::ListBoxRow = gtk::ListBoxRow::new();
                row_copy.add(&tx);
                listbox.add(&row_copy)
            }
            Ok(())
        }
        ToGraphic::WalletAdded(name) => {
            wallet_list.append_text(&name);
            Ok(())
        }
        ToGraphic::ProofOfInclusion(proof) => {
            if show_poi(proof).is_err() {
                error_window("Error en la generacion de la interfaz");
            }
            Ok(())
        }
        ToGraphic::BlockNotAvailable => {
            error_window("Bloque no disponible");
            Ok(())
        }
        ToGraphic::TransactionInformation(txid, amount, state, height, raw) => {
            if transaction_info(txid, amount, state, height, raw).is_err() {
                error_window("Error en la generacion de la interfaz");
            }
            Ok(())
        }
        ToGraphic::BlockAnnouncement(name, txid) => {
            set_state_txs(txs_grid.clone(), txid);
            setear_announcements(
                &mut announcement_0,
                &mut announcement_1,
                &mut announcement_2,
                &mut announcement_3,
                &name,
            );
            Ok(())
        }
        ToGraphic::BlockNewAnnouncement(announcement) | ToGraphic::TxAnnouncement(announcement) => {
            setear_announcements(
                &mut announcement_0,
                &mut announcement_1,
                &mut announcement_2,
                &mut announcement_3,
                &announcement,
            );
            Ok(())
        }
        ToGraphic::TransactionSent(id, amount) => {
            let tx = gtk::Label::new(Some(&id));
            let row_copy_: gtk::ListBoxRow = gtk::ListBoxRow::new();
            row_copy_.add(&tx);
            listbox.add(&row_copy_);
            insert_new_tx(txs_grid.clone(), recent_txs, id, amount);
            Ok(())
        }
        ToGraphic::NotProofOfInclusion => {
            error_window("No se pudo verificar la inclusion de la transaccion en el bloque");
            Ok(())
        }
        ToGraphic::EndInterface => Err(InterfaceError::LostCommunicationToHandler),
        ToGraphic::MyAddress(my_add) => {
            my_add_buff.set_text(&my_add);
            Ok(())
        }
    }
}

fn clear_information(address_to_pay: &gtk::Entry, amount: &gtk::SpinButton) {
    address_to_pay.delete_text(0, address_to_pay.text().len() as i32);
    amount.set_text("0,00000000");
}

fn ask_for_proof(sender: mpsc::Sender<FromGraphic>) -> Result<(), InterfaceError> {
    let builder = gtk::Builder::from_string(include_str!("proof_of_inclusion.glade"));
    match builder.object::<gtk::Window>("ask_poi_window") {
        Some(poi_window) => poi_window.show_all(),
        None => return Err(InterfaceError::CouldntCreateInterface),
    };

    let block_height_entry: gtk::Entry = try_open_gtk_objects(&builder, "block_height_entry")?;
    let txid_entry: gtk::Entry = try_open_gtk_objects(&builder, "txid_entry")?;
    let ask: gtk::Button = try_open_gtk_objects(&builder, "ask")?;

    ask.connect_clicked(move |_| {
        if sender
            .send(FromGraphic::GetProofOfInclusion(
                txid_entry.text().to_string(),
                block_height_entry.text().to_string(),
            ))
            .is_err()
        {
            return;
        }

        txid_entry.delete_text(0, txid_entry.text().len() as i32);
        block_height_entry.delete_text(0, block_height_entry.text().len() as i32);
    });

    Ok(())
}

fn add_wallet_fn(sender: mpsc::Sender<FromGraphic>) -> Result<(), InterfaceError> {
    let builder = gtk::Builder::from_string(include_str!("add_new_wallet.glade"));
    let window: gtk::Window = try_open_gtk_objects(&builder, "add_wall_window")?;
    window.show_all();
    let wind_cpy = window.clone();

    let wallet_privkey: gtk::Entry = try_open_gtk_objects(&builder, "wallet_privkey")?;
    let wallet_name1: gtk::Entry = try_open_gtk_objects(&builder, "wallet_name1")?;
    let wallet_name2: gtk::Entry = try_open_gtk_objects(&builder, "wallet_name2")?;
    let add: gtk::Button = try_open_gtk_objects(&builder, "add")?;
    let create: gtk::Button = try_open_gtk_objects(&builder, "create")?;

    let sender_copy = sender.clone();
    add.connect_clicked(move |_| {
        if wallet_name1.text().is_empty() {
            error_window("Error: Se requiere un nombre valido");
        } else if sender_copy
            .send(FromGraphic::AddWallet(
                wallet_name1.text().to_string(),
                wallet_privkey.text().to_string(),
            ))
            .is_err()
        {
            return;
        }

        wallet_privkey.delete_text(0, wallet_privkey.text().len() as i32);
        wallet_name1.delete_text(0, wallet_name1.text().len() as i32);
        window.close();
    });
    create.connect_clicked(move |_| {
        if wallet_name2.text().is_empty() {
            error_window("Error: Se requiere un nombre valido");
        } else if sender
            .send(FromGraphic::AddWallet(
                wallet_name2.text().to_string(),
                String::new(),
            ))
            .is_err()
        {
            return;
        }

        wallet_name2.delete_text(0, wallet_name2.text().len() as i32);
        wind_cpy.close();
    });
    Ok(())
}

fn clean_grid(grid: &mut gtk::Grid) {
    let rows = grid.children().len() / 3;
    for _ in 0..rows {
        grid.remove_row(0);
    }
}

fn clean_list(list_box: &gtk::ListBox) {
    for child in list_box.children() {
        list_box.remove(&child);
    }
}

fn set_all_txs(
    txs_grid: &mut gtk::Grid,
    recent_txs_grid: &mut gtk::Grid,
    items: Vec<[String; 3]>,
) -> Result<(), InterfaceError> {
    clean_grid(txs_grid);

    let rows = recent_txs_grid.children().len() / 2;
    for _ in 0..rows {
        recent_txs_grid.remove_row(0);
    }

    for (row, item) in items.iter().enumerate() {
        for (column, data) in item.iter().enumerate() {
            if column == 0 {
                if *data == "Confirmed" {
                    let imagen =
                        gtk::Image::from_icon_name(Some("dialog-ok"), gtk::IconSize::Button);
                    txs_grid.attach(&imagen, column as i32, row as i32, 1, 1);
                } else {
                    let imagen =
                        gtk::Image::from_icon_name(Some("appointment-new"), gtk::IconSize::Button);
                    txs_grid.attach(&imagen, column as i32, row as i32, 1, 1);
                }
            } else {
                let child = gtk::TextView::new();
                let buff = gtk::TextBuffer::new(None::<&gtk::TextTagTable>);
                child.set_buffer(Some(&buff));
                buff.set_text(data);
                child.set_editable(false);
                // let child = gtk::Label::new(Some(data));
                txs_grid.attach(&child, column as i32, row as i32, 1, 1);
            }
        }
    }

    for i in 0..5 {
        if i == items.len() {
            break;
        }
        let txid = items[i][1].clone();
        let label = gtk::Label::new(Some(&txid));
        let image =
            gtk::Image::from_icon_name(Some("accessories-calculator"), gtk::IconSize::Button);
        recent_txs_grid.attach(&image, 0, i as i32, 1, 1);
        recent_txs_grid.attach(&label, 1, i as i32, 1, 1);
    }

    Ok(())
}

fn set_state_txs(txs_grid: gtk::Grid, txid: String) {
    let rows = txs_grid.children().len() / 3;
    for row in 0..rows {
        if let Some(widget) = txs_grid.child_at(1, row as i32) {
            if let Some(label) = widget.downcast_ref::<gtk::Label>() {
                if label.text() == txid {
                    if let Some(image) = widget.downcast_ref::<gtk::Image>() {
                        txs_grid.remove(image);
                        let imagen =
                            gtk::Image::from_icon_name(Some("dialog-ok"), gtk::IconSize::Button);
                        txs_grid.attach(&imagen, 0, row as i32, 1, 1);
                    };
                };
            };
        };
    }
}

fn insert_new_tx(
    txs_grid: gtk::Grid,
    recent_txs_grid: &mut gtk::Grid,
    txid: String,
    amount: String,
) {
    /* Para agregar UNA fila (de tx) al grid (o lo que sea) */
    let next_row = txs_grid.children().len() / 3 + 1;
    let imagen = gtk::Image::from_icon_name(Some("appointment-new"), gtk::IconSize::Button);
    let txid_label = gtk::Label::new(Some(&txid));
    let amount = gtk::Label::new(Some(&amount));
    txs_grid.attach(&imagen, 0, next_row as i32, 1, 1);
    txs_grid.attach(&txid_label, 1, next_row as i32, 1, 1);
    txs_grid.attach(&amount, 2, next_row as i32, 1, 1);

    recent_txs_grid.remove_row(0);
    let label = gtk::Label::new(Some(&txid));
    let image = gtk::Image::from_icon_name(Some("accessories-calculator"), gtk::IconSize::Button);
    recent_txs_grid.attach(&image, 0, 4, 1, 1);
    recent_txs_grid.attach(&label, 1, 4, 1, 1);
}

fn show_poi(proof: String) -> Result<(), InterfaceError> {
    let builder = gtk::Builder::from_string(include_str!("proof_of_inclusion.glade"));
    match builder.object::<gtk::Window>("show_poi_window") {
        Some(poi_window) => poi_window.show_all(),
        None => return Err(InterfaceError::CouldntCreateInterface),
    };
    let poi_label: gtk::Label = builder.object("poi_label").unwrap();
    poi_label.set_text(&proof);
    Ok(())
}

fn update_window(
    sender: &mut mpsc::Sender<FromGraphic>,
    my_add: &mut gtk::TextView,
) -> Result<(), InterfaceError> {
    sender.send(FromGraphic::GetBalance)?;
    my_add.set_editable(true);
    sender.send(FromGraphic::GetMyAddr)?;
    my_add.set_editable(false);
    sender.send(FromGraphic::GetMyTransactions)?;
    Ok(sender.send(FromGraphic::GetTransactions)?)
}

/// Muestra la ventana principal del programa.
/// si el canal de comunicacion con el handler genera error al enviar informacion, la interfaz retorna a main
/// # Errors
/// * si no se creo correctamente algun elemento de la interfaz
pub fn graphic_interface(
    receiver_to_interface: glib::Receiver<ToGraphic>,
    sender_from: mpsc::Sender<FromGraphic>,
) -> Result<(), InterfaceError> {
    if gtk::init().is_err() {
        return Err(InterfaceError::CouldntCreateInterface);
    }

    // ---DECLARACION DE VARIABLES DE LA INTERFAZ---
    let builder = gtk::Builder::from_string(include_str!("graphic_interface.glade"));
    let window: gtk::Window = try_open_gtk_objects(&builder, "window")?;
    let send: gtk::Button = try_open_gtk_objects(&builder, "send")?;
    let clear: gtk::Button = try_open_gtk_objects(&builder, "clear")?;
    let label_with_amount: gtk::Label = try_open_gtk_objects(&builder, "label_with_amount")?;
    let txs_grid: gtk::Grid = try_open_gtk_objects(&builder, "txs_grid")?;
    let pay_to_entry: gtk::Entry = try_open_gtk_objects(&builder, "pay_to_entry")?;
    let amount_to_send: gtk::SpinButton = try_open_gtk_objects(&builder, "spin_button")?;
    let wallet_list: gtk::ComboBoxText = try_open_gtk_objects(&builder, "wallet_list")?;
    let add_wallet: gtk::Button = try_open_gtk_objects(&builder, "add_wallet")?;
    let poi_button: gtk::Button = try_open_gtk_objects(&builder, "proof_of_inclusion")?;
    let announcement_0: gtk::Label = try_open_gtk_objects(&builder, "block_download_0")?;
    let announcement_1: gtk::Label = try_open_gtk_objects(&builder, "block_download_1")?;
    let announcement_2: gtk::Label = try_open_gtk_objects(&builder, "block_download_2")?;
    let announcement_3: gtk::Label = try_open_gtk_objects(&builder, "block_download_3")?;
    let listbox: gtk::ListBox = try_open_gtk_objects(&builder, "listbox")?;
    let recent_txs: gtk::Grid = try_open_gtk_objects(&builder, "recent_txs")?;
    let mut my_add: gtk::TextView = try_open_gtk_objects(&builder, "my_add")?;
    let mut my_add_buff: gtk::TextBuffer = try_open_gtk_objects(&builder, "my_add_buf")?;

    // ---VARIABLES NECESARIAS PARA MANEJO---
    let mut sender_copy = sender_from.clone();
    let mut wallet_list_copy = wallet_list.clone();
    let mut label_with_amount_ = label_with_amount;
    let mut listbox_copy = listbox.clone();
    let window_clone = window.clone();
    let mut recent_txs_copy = recent_txs;
    let announcements = (
        announcement_0,
        announcement_1,
        announcement_2,
        announcement_3,
    );

    // ---SE QUEDA ESCUCHANDO EL RECEIVER---
    receiver_to_interface.attach(None, move |msg| {
        if handle_incoming(
            msg,
            &mut label_with_amount_,
            (&mut txs_grid.clone(), &mut recent_txs_copy),
            &mut sender_copy,
            (&mut wallet_list_copy, &mut listbox_copy),
            announcements.clone(),
            (&mut my_add_buff, &mut my_add),
        )
        .is_err()
        {
            gtk::main_quit();
        };
        window_clone.show_all();
        // Returning false here would close the receiver
        // and have senders fail
        glib::Continue(true)
    });

    // ---WRAPPERS DE EVENTOS DE LA INTERFAZ---
    let sender_copy = sender_from.clone();
    wallet_list.connect_changed(move |wallet_list| {
        if let Some(active_text) = wallet_list.active_text() {
            // ---BALANCE DE LA WALLET ELEGIDA---
            if sender_copy
                .send(FromGraphic::ChangeWallet(active_text.to_string()))
                .is_err()
            {
                gtk::main_quit();
            }
        }
    });

    //agregar nueva wallet
    let sender_cpy = sender_from.clone();
    add_wallet.connect_clicked(move |_add_wallet| {
        if add_wallet_fn(sender_cpy.clone()).is_err() {
            gtk::main_quit();
        }
    });

    // hace proof of inclusion
    let sender_cpy = sender_from.clone();
    poi_button.connect_clicked(move |_| {
        if ask_for_proof(sender_cpy.clone()).is_err() {
            error_window("Error en la generacion de la interfaz");
        };
    });

    // Send window
    let sender = sender_from.clone();
    let pay_to = pay_to_entry.clone();
    let amount_to_send_ = amount_to_send.clone();
    send.connect_clicked(move |_| {
        if transaction_to_send(&pay_to, &amount_to_send_, sender.clone()).is_err() {
            gtk::main_quit();
        }
        clear_information(&pay_to, &amount_to_send_);
    });
    let amount_to_send_ = amount_to_send;
    clear.connect_clicked(move |_| {
        clear_information(&pay_to_entry, &amount_to_send_);
    });

    //My Transactions window
    let sender_copy = sender_from.clone();
    let listbox_copy = listbox;
    listbox_copy.connect_row_selected(move |_, row| {
        if let Some(r) = row {
            if let Some(Ok(txid)) = r
                .child()
                .map(|row_child| row_child.downcast::<gtk::Label>())
            {
                if sender_copy
                    .send(FromGraphic::TransactionInformation(txid.text().to_string()))
                    .is_err()
                {
                    gtk::main_quit();
                }
            }
        }
    });

    window.show_all();
    window.connect_delete_event(move |_, _| {
        if sender_from.send(FromGraphic::EndGraphic).is_err() {
            return Inhibit(false);
        };
        gtk::main_quit();
        Inhibit(false)
    });
    gtk::main();
    Ok(())
}

/*privkey en wif: 92SD2oqjN8jUb33XoGmkkoGML1nRxBdcGZiXoqDL9xU1yowgHpJ
address:
mg5Xt8ogUKjj5oxxeDYdLvLUVSw7HNE6Cn

privkey en wif: 93JcZKAPezbqvV5Ntut5XCFZSowipPJJpWxkPnVgyaRRY1iVHjT
address: n1oeWx2DbzpB46xgMgt52EuR2JpsvvDuRx */
