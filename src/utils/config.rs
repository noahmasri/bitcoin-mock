//! Este modulo contiene el parseo de un archivo de configuracion
//! realizando los chequeos necesarios para su completitud.

use crate::utils::errors::ConfigurationError;
use chrono::{NaiveDate, Utc};
use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::net::{IpAddr, Ipv4Addr};

/// Esta estructura representa todos los datos que el usuario deberia proveer
#[derive(Debug, Clone)]
pub struct Config {
    /// Direccion IP del usuario
    pub ip_address: IpAddr,
    /// Puerto del usuario
    pub port: u16,
    /// Path de un archivo en que se loggearan todos los datos del usuario
    pub log_file_addr: String,
    /// Fecha a partir de la cual deberan descargarse todos los bloques completos
    pub start_date: NaiveDate,
    //optional fields
    /// Dominio del cual se tomaran las direcciones de los nodos a los que conectarse. Este campo no
    /// es obligatorio que sea proporcionado por el usuario.
    pub peers: Peers,
    /// Path de un archivo en que se guardaran los Encabezados de bloques descargados, y/o del que se tomaran encabezados ya escritos. Este campo no
    /// es obligatorio que sea proporcionado por el usuario.
    pub headers_file: String,
    /// Path de un directorio en que se guardaran bloques descargados. Este campo no
    /// es obligatorio que sea proporcionado por el usuario.
    pub blocks_dir: String,
}

#[derive(Debug, Clone)]
pub enum Peers {
    DOMAIN(String),
    ADDRESS(Vec<(IpAddr, u16)>),
}

struct ConfigCheck {
    ip_address: bool,
    port: bool,
    log_file_addr: bool,
    start_date: bool,
}

impl ConfigCheck {
    fn default() -> Self {
        ConfigCheck {
            ip_address: false,
            port: false,
            log_file_addr: false,
            start_date: false,
        }
    }

    fn all_fields_are_set(&self) -> bool {
        self.ip_address && self.port && self.log_file_addr && self.start_date
    }
}
impl Default for Config {
    fn default() -> Self {
        let fecha = match NaiveDate::from_ymd_opt(2023, 7, 10) {
            Some(f) => f,
            None => Utc::now().date_naive(),
        };

        Self {
            ip_address: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            port: 8080,
            log_file_addr: String::from("node.log"),
            start_date: fecha,
            peers: Peers::DOMAIN(String::from("seed.testnet.bitcoin.sprovoost.nl")),
            headers_file: String::from("headers.bin"),
            blocks_dir: String::from("blocks"),
        }
    }
}
impl Config {
    pub fn from_filepath(path: &str) -> Result<Config, ConfigurationError> {
        let file = File::open(path)?;
        Self::from_reader(file)
    }

    pub fn from_reader<T: Read>(file: T) -> Result<Config, ConfigurationError> {
        let reader = BufReader::new(file);
        let mut cfg = Self::default();
        let mut check = ConfigCheck::default();

        for line in reader.lines() {
            let current_line = line?;
            let setting: Vec<&str> = current_line.split('=').collect();
            if setting.len() != 2 {
                return Err(ConfigurationError::InvalidFormat);
            }
            Self::load_setting(&mut cfg, &mut check, setting[0], setting[1])?;
        }
        if !check.all_fields_are_set() {
            return Err(ConfigurationError::MissingArguments);
        }
        Ok(cfg)
    }

    //o esta el archivo completo y bien hecho, o va el default, descartamos archivo
    fn load_setting(
        &mut self,
        check: &mut ConfigCheck,
        name: &str,
        value: &str,
    ) -> Result<(), ConfigurationError> {
        match name {
            "IP_ADDRESS" => self.update_ip_address(check, value),
            "PORT" => self.update_port(check, value),
            "LOG_FILE" => self.update_log_file(check, value),
            "START_DATE" => self.update_start_date(check, value),
            "PEERS" => self.update_peers(value),
            "HEADERS" => {
                self.update_headers_file(value);
                Ok(())
            }
            "BLOCKS" => {
                self.update_blocks_dir(value);
                Ok(())
            }
            _ => Err(ConfigurationError::InvalidFieldName),
        }
    }

    fn update_ip_address(
        &mut self,
        check: &mut ConfigCheck,
        value: &str,
    ) -> Result<(), ConfigurationError> {
        if check.ip_address {
            return Err(ConfigurationError::RepeatedArguments);
        }

        self.ip_address = value.parse::<IpAddr>()?;
        check.ip_address = true;
        Ok(())
    }

    fn update_port(
        &mut self,
        check: &mut ConfigCheck,
        value: &str,
    ) -> Result<(), ConfigurationError> {
        if check.port {
            return Err(ConfigurationError::RepeatedArguments);
        }
        self.port = value.parse()?;
        check.port = true;
        Ok(())
    }

    fn update_log_file(
        &mut self,
        check: &mut ConfigCheck,
        value: &str,
    ) -> Result<(), ConfigurationError> {
        if check.log_file_addr {
            return Err(ConfigurationError::RepeatedArguments);
        }
        self.log_file_addr = value.to_string();
        check.log_file_addr = true;
        Ok(())
    }

    fn generate_addr_from_str(parts: Vec<&str>) -> Result<(IpAddr, u16), ConfigurationError> {
        if parts.len() != 2 {
            return Err(ConfigurationError::InvalidFormat);
        }
        let ip_address = parts[0].parse::<IpAddr>()?;
        let port = parts[1].parse()?;
        Ok((ip_address, port))
    }

    fn update_peers(&mut self, value: &str) -> Result<(), ConfigurationError> {
        let addresses: Vec<&str> = value.split(';').collect();
        if addresses.len() == 1 {
            let parts: Vec<&str> = value.split(':').collect();
            match parts.len() {
                1 => {
                    self.peers = Peers::DOMAIN(parts[0].to_string());
                }
                2 => {
                    let new_addr = Config::generate_addr_from_str(parts)?;
                    self.peers = Peers::ADDRESS(vec![new_addr]);
                }
                _ => {
                    return Err(ConfigurationError::InvalidFormat);
                }
            }
            return Ok(());
        }

        let mut peers = Vec::new();
        for addr in addresses {
            let new_addr = Config::generate_addr_from_str(addr.split(':').collect())?;
            peers.push(new_addr);
        }
        self.peers = Peers::ADDRESS(peers);
        Ok(())
    }

    fn update_headers_file(&mut self, value: &str) {
        self.headers_file = value.to_string();
    }

    fn update_blocks_dir(&mut self, value: &str) {
        self.blocks_dir = value.to_string();
    }

    fn update_start_date(
        &mut self,
        check: &mut ConfigCheck,
        value: &str,
    ) -> Result<(), ConfigurationError> {
        if check.start_date {
            return Err(ConfigurationError::RepeatedArguments);
        }

        self.start_date = match Self::convert_string_to_date(value) {
            Ok(value) => value,
            Err(a) => return Err(a),
        };
        check.start_date = true;
        Ok(())
    }

    fn convert_string_to_date(string: &str) -> Result<NaiveDate, ConfigurationError> {
        let date: Vec<_> = string.split('-').collect();
        if date.len() == 3 {
            let year = date[0].parse::<i32>()?;
            let month = date[1].parse::<u32>()?;
            let day = date[2].parse::<u32>()?;
            match NaiveDate::from_ymd_opt(year, month, day) {
                Some(value) => return Ok(value),
                None => return Err(ConfigurationError::InvalidFormat),
            };
        }
        Err(ConfigurationError::InvalidFormat)
    }

    #[must_use]
    pub fn get_address(&self) -> (IpAddr, u16) {
        (self.ip_address, self.port)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::errors::ConfigurationError;

    #[test]
    fn config_is_created_from_file_path() {
        match Config::from_filepath("config_tests/example1.txt") {
            Ok(config) => {
                assert_eq!(String::from("127.0.0.1"), (config.ip_address).to_string());
                assert_eq!(8080, config.port);
                assert_eq!(String::from("node.log"), config.log_file_addr);
                assert_eq!(String::from("2023-06-23"), config.start_date.to_string());
            }
            Err(_err) => {
                panic!();
            }
        }
    }

    #[test]
    fn config_is_created_from_buf_reader() {
        let content = "IP_ADDRESS=192.168.1.136\n\
        PORT=63\n\
        LOG_FILE=pruebas_config/log.txt\n\
        START_DATE=2001-3-5"
            .as_bytes();

        match Config::from_reader(content) {
            Ok(config) => {
                assert_eq!(
                    String::from("192.168.1.136"),
                    (config.ip_address).to_string()
                );
                assert_eq!(63, config.port);
                assert_eq!(String::from("pruebas_config/log.txt"), config.log_file_addr);
                assert_eq!(String::from("2001-03-05"), config.start_date.to_string());
            }
            Err(_err) => {
                panic!();
            }
        }
    }
    #[test]
    fn config_is_created_from_filepath_with_fields_in_different_orders() {
        match Config::from_filepath("config_tests/example2.txt") {
            Ok(config) => {
                assert_eq!(
                    String::from("192.168.1.136"),
                    (config.ip_address).to_string()
                );
                assert_eq!(63, config.port);
                assert_eq!(String::from("pruebas_config/log.txt"), config.log_file_addr);
                assert_eq!(String::from("2001-03-05"), config.start_date.to_string());
            }
            Err(_err) => {
                panic!();
            }
        }
    }
    #[test]
    fn config_is_not_created_if_too_many_arguments() {
        let config = Config::from_filepath("config_tests/repeated1.txt");
        assert!(config.is_err());
        assert!(matches!(config, Err(ConfigurationError::RepeatedArguments)));

        let other_config = Config::from_filepath("config_tests/repeated2.txt");
        assert!(other_config.is_err());
        assert!(matches!(
            other_config,
            Err(ConfigurationError::RepeatedArguments)
        ));
    }
    #[test]
    fn config_is_not_created_if_missing_arguments() {
        let config = Config::from_filepath("config_tests/missing_fields.txt");
        assert!(config.is_err());
        assert!(matches!(config, Err(ConfigurationError::MissingArguments)));
    }

    #[test]
    fn config_can_be_created_with_multiple_peer_addresses() {
        match Config::from_filepath("config_tests/config_ips.txt") {
            Ok(config) => {
                assert_eq!(String::from("127.0.0.1"), (config.ip_address).to_string());
                assert_eq!(8084, config.port);
                assert_eq!(String::from("node_client.log"), config.log_file_addr);
                assert_eq!(String::from("2023-06-23"), config.start_date.to_string());
                match config.peers {
                    Peers::ADDRESS(addrs) => {
                        assert_eq!(addrs.len(), 2);
                        assert_eq!(addrs[0].0.to_string(), String::from("127.0.0.1"));
                        assert_eq!(addrs[0].1, 18333);
                        assert_eq!(addrs[1].0.to_string(), String::from("192.168.1.136"));
                        assert_eq!(addrs[1].1, 20);
                    }
                    Peers::DOMAIN(_) => panic!(),
                }
            }
            Err(_err) => {
                panic!();
            }
        }
    }

    #[test]
    fn config_is_not_created_if_date_format_is_incorrect() {
        let config = Config::from_filepath("config_tests/not_numeric_dates.txt");
        assert!(config.is_err());
        assert!(matches!(config, Err(ConfigurationError::InvalidFormat)));

        let other_config = Config::from_filepath("config_tests/missing_date_fields.txt");
        assert!(other_config.is_err());
        assert!(matches!(
            other_config,
            Err(ConfigurationError::InvalidFormat)
        ));
    }
    #[test]
    fn config_is_not_created_if_ip_is_invalid() {
        let config = Config::from_filepath("config_tests/invalid_ip.txt");
        assert!(config.is_err());
        assert!(matches!(config, Err(ConfigurationError::InvalidIP)));
    }

    #[test]
    fn config_is_not_created_if_port_is_invalid() {
        let config = Config::from_filepath("config_tests/invalid_port.txt");
        assert!(config.is_err());
        assert!(matches!(config, Err(ConfigurationError::InvalidFormat)));
    }
    #[test]
    fn config_is_not_created_if_line_format_is_incorrect() {
        let config = Config::from_filepath("config_tests/invalid_line.txt");
        assert!(config.is_err());
        assert!(matches!(config, Err(ConfigurationError::InvalidFormat)));
    }
}
