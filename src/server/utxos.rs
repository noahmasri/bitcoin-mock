//! Este modulo contiene todas las funciones necesarias para,
//! dado un vector de bloques, poder devolver obtener estructura
//! que tenga todos los outputs no gastados

use bitcoin_hashes::{ripemd160, sha256, Hash};

const OP_DUP: u8 = 0x76;
const OP_HASH160: u8 = 0xa9;
const OP_PUSH_BYTES_20: u8 = 0x14;
use crate::server::blocks::Block;
use crate::utils::errors::UtxoError;
use crate::utils::tx::Transaction;
use std::collections::HashMap;
use std::io::Read;

use super::blockdownload::Blockchain;

/// Estructura que contiene toda la informacion que necesita un usuario para poder usar sus outputs como inputs para futuras transacciones
#[derive(Clone, Copy, Debug)]
pub struct UtxoInfo {
    pub block_height: u32,
    pub amount: i64,
    pub txid: [u8; 32],
    pub index: u32,
}

impl UtxoInfo {
    /// A partir de un valor, el hash de una transaccion y un indice, settea todos los parametros de la estructura
    pub fn new(block_height: u32, amount: i64, txid: [u8; 32], index: u32) -> UtxoInfo {
        UtxoInfo {
            block_height,
            amount,
            txid,
            index,
        }
    }
    /// Convierte una instancia de la estructura a bytes para poder enviarla por un stream
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.block_height.to_le_bytes());
        buf.extend_from_slice(&self.amount.to_le_bytes());
        buf.extend_from_slice(&self.txid);
        buf.extend_from_slice(&self.index.to_le_bytes());
        buf
    }
    /// Convierte los bytes leidos de alguna variable que implemente el trait read a una instancia de este
    pub fn from_bytes(stream: &mut dyn Read) -> Result<Self, UtxoError> {
        let mut buf_block_height: [u8; 4] = [0; 4];
        let mut buf_amount: [u8; 8] = [0; 8];
        let mut buf_txid: [u8; 32] = [0; 32];
        let mut buf_index: [u8; 4] = [0; 4];

        stream.read_exact(&mut buf_block_height)?;
        stream.read_exact(&mut buf_amount)?;
        stream.read_exact(&mut buf_txid)?;
        stream.read_exact(&mut buf_index)?;

        Ok(Self::new(
            <u32>::from_le_bytes(buf_block_height),
            <i64>::from_le_bytes(buf_amount),
            buf_txid,
            <u32>::from_le_bytes(buf_index),
        ))
    }
}

/// Devuelve, dado un vector de bloques ordenado cronologicamente, un hashmap cuya clave es el hash de la clave publica del propietario, y
/// cuyo valor son los outputs en formato UtxoInfo
pub fn get_utxo_set(blockchain: &mut Blockchain) {
    let mut hashmap: HashMap<[u8; 20], Vec<UtxoInfo>> = HashMap::new();
    for header in blockchain.block_headers.list.iter() {
        if let Some(block) = blockchain.blocks.get(&header.hash()) {
            update_hash_with_block(block, &mut hashmap);
        }
    }
    blockchain.utxo_set = hashmap;
}

/// Actualiza el hashmap recibido con la informacion contenida en el bloque
pub fn update_hash_with_block(block: &Block, hashmap: &mut HashMap<[u8; 20], Vec<UtxoInfo>>) {
    for transaction in block.txs.iter() {
        for input in transaction.tx_in.iter() {
            //veo quien hizo esta transaccion del bloque
            if let Ok(pk_hash_of_spender) = get_pkhash_from_sigscript(&input.signature_script) {
                //busco todos los utxos de este

                if let Some(mut utxos) = hashmap.remove(&pk_hash_of_spender) {
                    //veo cual utxo uso como input
                    for (i, utxo) in utxos.iter().enumerate() {
                        //una vez que coincide el utxo con el previous outpoint, la saco y salgo del bucle
                        if utxo.txid == input.previous_outpoint.hash
                            && utxo.index == input.previous_outpoint.index
                        {
                            utxos.remove(i);
                            break;
                        }
                    }
                    //vuelvo a insertar al hashmap el set de utxos actualizado
                    hashmap.insert(pk_hash_of_spender, utxos);
                }
            }
        }
    }

    let key_val_sets = get_all_key_value_sets(block.height(), &block.txs);
    for (pk_hash, utxo_info) in key_val_sets {
        //ya habian utxos de esa cuenta
        if let Some(mut utxos) = hashmap.remove(&pk_hash) {
            utxos.push(utxo_info);
            hashmap.insert(pk_hash, utxos);
        } else {
            hashmap.insert(pk_hash, vec![utxo_info]);
        }
    }
}

/// Dado un signature script del input de una transaccion, obtiene el hash de la clave publica de
/// quien hizo el gasto. Soporta unicamente el formato P2PKH
/// # Errors
/// * Si el formato del signature script no es el usado por P2PKH, devuelve UtxoError::CouldntObtainPkHash
pub fn get_pkhash_from_sigscript(sig_script: &Vec<u8>) -> Result<[u8; 20], UtxoError> {
    if sig_script.is_empty() {
        //no sig script, has witness
        return Err(UtxoError::CouldntObtainPkHash);
    }
    let mut sig_clone = sig_script.clone();
    let push_bytes_in_u8: Vec<_> = sig_clone.drain(..1).collect();
    let sig_size = <usize>::from(push_bytes_in_u8[0]);
    if sig_size > sig_clone.len() {
        //other format, cannot calculate pkhash from this
        return Err(UtxoError::CouldntObtainPkHash);
    }
    sig_clone.drain(..sig_size);
    if !sig_clone.is_empty() {
        sig_clone.drain(..1);
        return Ok(
            ripemd160::Hash::hash(&sha256::Hash::hash(&sig_clone).to_byte_array()).to_byte_array(),
        );
    }
    Err(UtxoError::CouldntObtainPkHash)
}

/// Dado un public key script del output de una transaccion, obtiene el hash de la clave publica del destinatario de la transaccion.
/// Soporta unicamente el formato P2PKH
/// # Errors
/// * Si el formato del script no es el usado por P2PKH, devuelve UtxoError::CouldntObtainPkHash
pub fn get_pkhash_from_pkscript(script: &Vec<u8>) -> Result<[u8; 20], UtxoError> {
    let mut script_clone = script.clone();
    if script.len() < 3 {
        return Err(UtxoError::CouldntObtainPkHash);
    }
    let rest: Vec<u8> = script_clone.drain(0..3).collect();
    if rest != vec![OP_DUP, OP_HASH160, OP_PUSH_BYTES_20] || script_clone.len() < 2 {
        return Err(UtxoError::CouldntObtainPkHash);
    }
    script_clone.truncate(script_clone.len() - 2);
    let pkhash: [u8; 20] = script_clone.try_into()?;
    Ok(pkhash)
}

fn get_all_key_value_sets(
    block_height: u32,
    transactions: &Vec<Transaction>,
) -> Vec<([u8; 20], UtxoInfo)> {
    let mut outputs: Vec<([u8; 20], UtxoInfo)> = Vec::new();
    for tx in transactions {
        let hash_trans = tx.hash();
        for (i, out) in tx.tx_out.iter().enumerate() {
            if let Ok(index) = u32::try_from(i) {
                if let Ok(pk_hash) = get_pkhash_from_pkscript(&out.pk_script) {
                    let value = UtxoInfo::new(block_height, out.value, hash_trans, index);
                    outputs.push((pk_hash, value));
                }
            }
        }
    }
    outputs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn can_get_pk_from_signature_script() {
        let sig_script = "483045022100d4ca49ea9f177be4c5f8ea7092ae5e259b8f25d04d8c28c0ff0dd9527022661202201a48fdd9bec728d83952b31ab5ab26c6a750ad2949f26430e7f8aad918a8ea2c0121032583a2fb00ad4f9ac6630563ec2efadc900c5ea3308ce2ca881489ba835d1153";
        let hexa_script_bytes = hex::decode(sig_script).unwrap();
        let pk_hash = get_pkhash_from_sigscript(&hexa_script_bytes).unwrap();
        let pk_in_str = "032583a2fb00ad4f9ac6630563ec2efadc900c5ea3308ce2ca881489ba835d1153";
        let pk = hex::decode(pk_in_str).unwrap();
        let pk_real_hash =
            ripemd160::Hash::hash(&sha256::Hash::hash(&pk).to_byte_array()).to_byte_array();
        assert_eq!(pk_hash, pk_real_hash);
    }
    #[test]
    fn cant_get_pk_from_signature_script() {
        let sig_script = "535203945187";
        let hexa_script_bytes = hex::decode(sig_script).unwrap();
        assert!(get_pkhash_from_sigscript(&hexa_script_bytes).is_err());
    }
    #[test]
    fn can_get_pk_hash_from_pk_script() -> Result<(), UtxoError> {
        let pk_script = "76a914ba27f99e007c7f605a8305e318c1abde3cd220ac88ac";
        let hexa_script_bytes = hex::decode(pk_script).unwrap();
        let pk_hash = get_pkhash_from_pkscript(&hexa_script_bytes).unwrap();
        let pk_hash_in_str = "ba27f99e007c7f605a8305e318c1abde3cd220ac";
        let real_pk_hash_in_vec = hex::decode(pk_hash_in_str).unwrap();
        let real_pk_hash: [u8; 20] = real_pk_hash_in_vec.try_into()?;
        assert_eq!(pk_hash, real_pk_hash);
        Ok(())
    }

    #[test]
    fn cant_get_pk_hash_from_pk_script() -> Result<(), UtxoError> {
        let pk_script = "a914aa6be06f06576339ee05064561286eb719ad5baa87";
        let hexa_script_bytes = hex::decode(pk_script).unwrap();
        assert!(get_pkhash_from_pkscript(&hexa_script_bytes).is_err());
        Ok(())
    }
}
