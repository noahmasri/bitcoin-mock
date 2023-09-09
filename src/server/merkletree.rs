//! Este modulo contiene todas las funciones necesarias para construir el merkle tree
//! con todas las transacciones de un bloque. Ademas de la funciones de proof of work y parseo de un proof of inclusion.
use crate::utils::errors::MerkleError;
use bitcoin_hashes::{sha256d, Hash};

/// Estructura de la proof of inclusion de una
/// determinada transaccion en un determinado merkle tree.
pub struct MerkleProof {
    tx_to_verify: [u8; 32],
    merkleroot: [u8; 32],
    hashes: Vec<[u8; 32]>,
    flags: Vec<bool>,
}

impl MerkleProof {
    /// Crea una nueva instancia de MerkleProof.
    /// Recibe la transaccion a verificar, el merkleroot del
    /// bloque al que pertenece la transaccion, la secuencia
    /// de hashes a combinar con sus respectivos flags (path).
    /// Los flags deben estar ordenados con el orden de los hashes.
    ///
    /// # Errors
    /// * si la cantidad de hashes no es la misma que la de flags.
    pub fn new(
        tx_to_verify: [u8; 32],
        merkleroot: [u8; 32],
        hashes: Vec<[u8; 32]>,
        flags: Vec<bool>,
    ) -> Result<Self, MerkleError> {
        if hashes.len() != flags.len() {
            return Err(MerkleError::ErrorInProofPath);
        }
        Ok(MerkleProof {
            tx_to_verify,
            merkleroot,
            hashes,
            flags,
        })
    }

    /// Verifica la proof of inclusion (poi).
    /// Devuelve true en caso de que la transaccion
    /// a verificar derive en el merkleroot, a traves
    /// del path (hashes y flags).
    /// Devuelve false en caso contrario.
    pub fn verify_proof(&self) -> bool {
        let mut cur_hash = self.tx_to_verify;
        for i in 0..self.flags.len() {
            if self.flags[i] {
                cur_hash = merge_hashes(&cur_hash, &self.hashes[i]);
            } else {
                cur_hash = merge_hashes(&self.hashes[i], &cur_hash);
            }
        }

        cur_hash == self.merkleroot
    }

    /// Devuelve la prueba (path) de que la transaccion pertenece
    /// al merkletree respectivo.
    #[must_use]
    pub fn get_proof(&self) -> Vec<([u8; 32], [u8; 32])> {
        let mut path = vec![];
        let mut cur_hash = self.tx_to_verify;
        for i in 0..self.flags.len() {
            let cur_layer;
            if self.flags[i] {
                cur_layer = (cur_hash, self.hashes[i]);
                cur_hash = merge_hashes(&cur_hash, &self.hashes[i]);
            } else {
                cur_layer = (self.hashes[i], cur_hash);
                cur_hash = merge_hashes(&self.hashes[i], &cur_hash);
            }
            path.push(cur_layer);
        }
        path
    }

    /// Devuelve el id de la transaccion a verificar.
    pub fn get_tx_id(&self) -> [u8; 32] {
        self.tx_to_verify
    }
}

/// Estructura del Merkle Tree que contiene su merkleroot.
#[derive(Debug, Clone)]
pub struct MerkleTree {
    pub root: [u8; 32],
    hash_layers: Vec<Vec<[u8; 32]>>,
}

fn merge_hashes(left_hash: &[u8; 32], right_hash: &[u8; 32]) -> [u8; 32] {
    let mut hashes_concatenated = vec![];
    hashes_concatenated.extend_from_slice(left_hash);
    hashes_concatenated.extend_from_slice(right_hash);
    let higher_level_hash = sha256d::Hash::hash(&hashes_concatenated);
    higher_level_hash.to_byte_array()
}

impl MerkleTree {
    /// Crea una nueva instancia de MerkleTree.
    /// Recibe el merlkeroot y las capas restantes del arbol.
    pub fn new(root: [u8; 32], hash_layers: Vec<Vec<[u8; 32]>>) -> Self {
        MerkleTree { root, hash_layers }
    }

    fn build_merkle_tree(leafs: &[[u8; 32]]) -> ([u8; 32], Vec<Vec<[u8; 32]>>) {
        if leafs.len() == 1 {
            return (leafs[0], vec![vec![]]);
        }
        let mut tree_rows = vec![];
        let mut curr_row: Vec<[u8; 32]> = leafs.to_vec();

        while curr_row.len() > 1 {
            let mut next_row = vec![];
            tree_rows.push(curr_row.clone());
            for i in (0..curr_row.len()).step_by(2) {
                if i == curr_row.len() - 1 {
                    let merged_hash = merge_hashes(&curr_row[i], &curr_row[i]);
                    next_row.push(merged_hash);
                } else {
                    let merged_hash = merge_hashes(&curr_row[i], &curr_row[i + 1]);
                    next_row.push(merged_hash);
                }
            }
            curr_row = next_row;
        }

        let root = curr_row[0];
        let hash_layers = tree_rows;

        (root, hash_layers)
    }

    /// Crea una nueva instancia de MerkleTree a partir de una
    /// secuencia de transacciones.
    ///
    /// # Errors
    /// * si recibe una secuencia vacia.
    pub fn from_txs(txs_ids: &[[u8; 32]]) -> Result<MerkleTree, MerkleError> {
        if txs_ids.is_empty() {
            return Err(MerkleError::NoTXsToMerkle);
        }

        let (root, hash_layers) = MerkleTree::build_merkle_tree(txs_ids);

        Ok(Self::new(root, hash_layers))
    }

    /// Verifica que el merkleroot pasado por parametro sea el mismo
    /// que el generado a partir de las transacciones del struct.
    pub fn verify_merkle_root(&self, merkleroot: [u8; 32]) -> bool {
        self.root == merkleroot
    }

    fn search_tx(&self, tx_id: &[u8; 32]) -> Result<usize, MerkleError> {
        for (idx, cur_tx_id) in self.hash_layers[0].iter().enumerate() {
            if *cur_tx_id == *tx_id {
                return Ok(idx);
            }
        }
        Err(MerkleError::TxIdNotFound)
    }

    /// Realiza el proof of inclusion (poi) de la transaccion que recibe por parametro.
    /// Si no hay error, devuelve la proof.
    ///
    /// # Errors
    /// * si la transaccion no se encuentra en el arbol.
    pub fn proof_of_inclusion(&self, tx_id: &[u8; 32]) -> Result<MerkleProof, MerkleError> {
        let tx_idx = self.search_tx(tx_id)?;
        let mut hashes = vec![];
        let mut flags = vec![];

        let mut node_idx = tx_idx;
        for layer in self.hash_layers.iter() {
            if node_idx % 2 == 0 {
                if node_idx == layer.len() - 1 {
                    hashes.push(layer[node_idx]);
                } else {
                    hashes.push(layer[node_idx + 1]);
                }
                flags.push(true);
            } else {
                hashes.push(layer[node_idx - 1]);
                flags.push(false);
            }
            node_idx /= 2;
        }

        MerkleProof::new(*tx_id, self.root, hashes, flags)
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_poi_2_txs() {
        let tx1_str = "e9d99a4993dbffbfdb27e606405a7feaf75779f4e664d75c336f05dce6c6ea9d";
        let tx1 = sha256d::Hash::from_str(tx1_str).unwrap();
        let tx1_bytes = tx1.to_byte_array();

        let tx2_str = "27eb7f0b4b1c474a6d2d0eabb00dc57c9c1fc772671f000ec6965d0b2d0638ce";
        let tx2 = sha256d::Hash::from_str(tx2_str).unwrap();
        let tx2_bytes = tx2.to_byte_array();

        let merkletree = match MerkleTree::from_txs(&[tx1_bytes, tx2_bytes]) {
            Ok(merkle) => merkle,
            Err(_) => panic!(),
        };

        let poi_for_tx1 = merkletree.proof_of_inclusion(&tx1_bytes).unwrap();
        let poi_for_tx2 = merkletree.proof_of_inclusion(&tx2_bytes).unwrap();

        assert_eq!(
            (poi_for_tx1.hashes, poi_for_tx1.flags),
            (vec![tx2_bytes], vec![true])
        );
        assert_eq!(
            (poi_for_tx2.hashes, poi_for_tx2.flags),
            (vec![tx1_bytes], vec![false])
        );
    }

    #[test]
    fn test_poi_3_txs() {
        let tx1_str = "c6c19733413abb24057159f87273c7c3de6a9f93c950e0b40ff8b771b6d6b254";
        let tx1 = sha256d::Hash::from_str(tx1_str).unwrap();
        let tx1_bytes = tx1.to_byte_array();

        let tx2_str = "435f717b5d64d98f358fbda856d86705a4df62a210a2fe5524b2c3311ceefc9f";
        let tx2 = sha256d::Hash::from_str(tx2_str).unwrap();
        let tx2_bytes = tx2.to_byte_array();

        let tx3_str = "d049d496329c823abc5d07da4b03c459428d082f8f50bc687fc6cd064c1a6175";
        let tx3 = sha256d::Hash::from_str(tx3_str).unwrap();
        let tx3_bytes = tx3.to_byte_array();

        let hash12 = merge_hashes(&tx1_bytes, &tx2_bytes);
        let hash33 = merge_hashes(&tx3_bytes, &tx3_bytes);

        let merkletree = match MerkleTree::from_txs(&[tx1_bytes, tx2_bytes, tx3_bytes]) {
            Ok(merkle) => merkle,
            Err(_) => panic!(),
        };

        let poi_for_tx1 = merkletree.proof_of_inclusion(&tx1_bytes).unwrap();
        let poi_for_tx2 = merkletree.proof_of_inclusion(&tx2_bytes).unwrap();
        let poi_for_tx3 = merkletree.proof_of_inclusion(&tx3_bytes).unwrap();

        assert_eq!(
            (poi_for_tx1.hashes, poi_for_tx1.flags),
            (vec![tx2_bytes, hash33], vec![true, true])
        );
        assert_eq!(
            (poi_for_tx2.hashes, poi_for_tx2.flags),
            (vec![tx1_bytes, hash33], vec![false, true])
        );
        assert_eq!(
            (poi_for_tx3.hashes, poi_for_tx3.flags),
            (vec![tx3_bytes, hash12], vec![true, false])
        );
    }

    #[test]
    fn test_verify_poi_2_txs() {
        let tx1_str = "e9d99a4993dbffbfdb27e606405a7feaf75779f4e664d75c336f05dce6c6ea9d";
        let tx1 = sha256d::Hash::from_str(tx1_str).unwrap();
        let tx1_bytes = tx1.to_byte_array();

        let tx2_str = "27eb7f0b4b1c474a6d2d0eabb00dc57c9c1fc772671f000ec6965d0b2d0638ce";
        let tx2 = sha256d::Hash::from_str(tx2_str).unwrap();
        let tx2_bytes = tx2.to_byte_array();

        let real_merkleroot_str =
            "f5df0de2bdf78bdc19f7dce80e40b683ffa447431a0ad190cd0433ee86036acd";
        let real_merkleroot = sha256d::Hash::from_str(real_merkleroot_str).unwrap();
        let real_merkleroot_bytes = real_merkleroot.to_byte_array();

        let merkletree = MerkleTree::from_txs(&[tx1_bytes, tx2_bytes]).unwrap();

        assert_eq!(merkletree.root, real_merkleroot_bytes);

        let poi_for_tx1 = merkletree.proof_of_inclusion(&tx1_bytes).unwrap();
        let poi_for_tx2 = merkletree.proof_of_inclusion(&tx2_bytes).unwrap();

        assert!(poi_for_tx1.verify_proof());
        assert!(poi_for_tx2.verify_proof());
    }

    #[test]
    fn test_verify_poi_3_txs() {
        let tx1_str = "c6c19733413abb24057159f87273c7c3de6a9f93c950e0b40ff8b771b6d6b254";
        let tx1 = sha256d::Hash::from_str(tx1_str).unwrap();
        let tx1_bytes = tx1.to_byte_array();

        let tx2_str = "435f717b5d64d98f358fbda856d86705a4df62a210a2fe5524b2c3311ceefc9f";
        let tx2 = sha256d::Hash::from_str(tx2_str).unwrap();
        let tx2_bytes = tx2.to_byte_array();

        let tx3_str = "d049d496329c823abc5d07da4b03c459428d082f8f50bc687fc6cd064c1a6175";
        let tx3 = sha256d::Hash::from_str(tx3_str).unwrap();
        let tx3_bytes = tx3.to_byte_array();

        let real_merkleroot_str =
            "1ed6d8205b8abfd9789c7c62bee16d86ce43f99689d5aac26fd43035bceacb08";
        let real_merkleroot = sha256d::Hash::from_str(real_merkleroot_str).unwrap();
        let real_merkleroot_bytes = real_merkleroot.to_byte_array();

        let merkletree = MerkleTree::from_txs(&[tx1_bytes, tx2_bytes, tx3_bytes]).unwrap();

        assert_eq!(merkletree.root, real_merkleroot_bytes);

        let poi_for_tx1 = merkletree.proof_of_inclusion(&tx1_bytes).unwrap();
        let poi_for_tx2 = merkletree.proof_of_inclusion(&tx2_bytes).unwrap();
        let poi_for_tx3 = merkletree.proof_of_inclusion(&tx3_bytes).unwrap();

        assert!(poi_for_tx1.verify_proof());
        assert!(poi_for_tx2.verify_proof());
        assert!(poi_for_tx3.verify_proof());
    }

    /*
            AB
           A  B
    */
    #[test]
    fn test_2_txs() {
        let tx1_str = "e9d99a4993dbffbfdb27e606405a7feaf75779f4e664d75c336f05dce6c6ea9d";
        let tx1 = sha256d::Hash::from_str(tx1_str).unwrap();
        let tx1_bytes = tx1.to_byte_array();

        let tx2_str = "27eb7f0b4b1c474a6d2d0eabb00dc57c9c1fc772671f000ec6965d0b2d0638ce";
        let tx2 = sha256d::Hash::from_str(tx2_str).unwrap();
        let tx2_bytes = tx2.to_byte_array();

        let real_merkleroot_str =
            "f5df0de2bdf78bdc19f7dce80e40b683ffa447431a0ad190cd0433ee86036acd";
        let real_merkleroot = sha256d::Hash::from_str(real_merkleroot_str).unwrap();
        let real_merkleroot_bytes = real_merkleroot.to_byte_array();

        let merkletree = MerkleTree::from_txs(&[tx1_bytes, tx2_bytes]).unwrap();

        assert!(merkletree.verify_merkle_root(real_merkleroot_bytes));
    }

    /*
            ABC
          AB   CC
         A  B C
    */
    #[test]
    fn test_3_txs() {
        let tx1_str = "c6c19733413abb24057159f87273c7c3de6a9f93c950e0b40ff8b771b6d6b254";
        let tx1 = sha256d::Hash::from_str(tx1_str).unwrap();
        let tx1_bytes = tx1.to_byte_array();

        let tx2_str = "435f717b5d64d98f358fbda856d86705a4df62a210a2fe5524b2c3311ceefc9f";
        let tx2 = sha256d::Hash::from_str(tx2_str).unwrap();
        let tx2_bytes = tx2.to_byte_array();

        let tx3_str = "d049d496329c823abc5d07da4b03c459428d082f8f50bc687fc6cd064c1a6175";
        let tx3 = sha256d::Hash::from_str(tx3_str).unwrap();
        let tx3_bytes = tx3.to_byte_array();

        let real_merkleroot_str =
            "1ed6d8205b8abfd9789c7c62bee16d86ce43f99689d5aac26fd43035bceacb08";
        let real_merkleroot = sha256d::Hash::from_str(real_merkleroot_str).unwrap();
        let real_merkleroot_bytes = real_merkleroot.to_byte_array();

        let merkletree = MerkleTree::from_txs(&[tx1_bytes, tx2_bytes, tx3_bytes]).unwrap();

        assert!(merkletree.verify_merkle_root(real_merkleroot_bytes));
    }

    /*
               ABCDEEEE
           ABCD       EEEE
         AB    CD   EE
        A  B  C  D E
    */
    #[test]
    fn test_5_txs() {
        let tx1_str = "95c00e6418642bfb4f7429692d7c9ef5c66de3d7bfb58a6c2d0575fa97fa6258";
        let tx1 = sha256d::Hash::from_str(tx1_str).unwrap();
        let tx1_bytes = tx1.to_byte_array();

        let tx2_str = "4f5465179fccfa8bf2d82e06e6cc3c1da24863c1b6a8be802ca96958ff1946fd";
        let tx2 = sha256d::Hash::from_str(tx2_str).unwrap();
        let tx2_bytes = tx2.to_byte_array();

        let tx3_str = "a6d04573c648752ed117f2f5daa66b7504d899a09f714366199619de3f0b5536";
        let tx3 = sha256d::Hash::from_str(tx3_str).unwrap();
        let tx3_bytes = tx3.to_byte_array();

        let tx4_str = "0b9fba1ef4eac893d49f05e4c225a3367becf40da16b8582b01cbf92f189f987";
        let tx4 = sha256d::Hash::from_str(tx4_str).unwrap();
        let tx4_bytes = tx4.to_byte_array();

        let tx5_str = "2fee3e07303d4076718a9d34b7abbb8beb7cbbf53f1385212a4fc84d8759c4c6";
        let tx5 = sha256d::Hash::from_str(tx5_str).unwrap();
        let tx5_bytes = tx5.to_byte_array();

        let real_merkleroot_str =
            "daf9070040748f2859f271db60707d62a2db157cf5a157e93917ba8b325b0291";
        let real_merkleroot = sha256d::Hash::from_str(real_merkleroot_str).unwrap();
        let real_merkleroot_bytes = real_merkleroot.to_byte_array();

        let merkletree =
            MerkleTree::from_txs(&[tx1_bytes, tx2_bytes, tx3_bytes, tx4_bytes, tx5_bytes]).unwrap();

        assert!(merkletree.verify_merkle_root(real_merkleroot_bytes));
    }

    /*
               ABCDEFEF
            ABCD      EFEF
          AB    CD    EF
         A  B  C  D  E  F
    */
    #[test]
    fn test_6_txs() {
        let tx1_str = "21072dea56da0ce4db02d9cc6cf044bc84d4739aea515b1353ae65201de0a055";
        let tx1 = sha256d::Hash::from_str(tx1_str).unwrap();
        let tx1_bytes = tx1.to_byte_array();

        let tx2_str = "81e2a7cdb5189fbb39870fbc42882bf2ca0b58f22dfa671a6f4580c2d8398066";
        let tx2 = sha256d::Hash::from_str(tx2_str).unwrap();
        let tx2_bytes = tx2.to_byte_array();

        let tx3_str = "0410dea589324358241babb14ddb80ba4c398d541a0b296f07073954d3383cc9";
        let tx3 = sha256d::Hash::from_str(tx3_str).unwrap();
        let tx3_bytes = tx3.to_byte_array();

        let tx4_str = "f088fc9282dec5da9dff563ad7d8f2fbc9b978d7a9f7ad95e76f0b9506d5b184";
        let tx4 = sha256d::Hash::from_str(tx4_str).unwrap();
        let tx4_bytes = tx4.to_byte_array();

        let tx5_str = "11f0f770e44ded78810b089986992d608a885a7cf113ad1f94dfd43222042606";
        let tx5 = sha256d::Hash::from_str(tx5_str).unwrap();
        let tx5_bytes = tx5.to_byte_array();

        let tx6_str = "6d54df72fe7f7b09be2f1a3f56081d71232765edc0520c022c4fce9b6b73eb48";
        let tx6 = sha256d::Hash::from_str(tx6_str).unwrap();
        let tx6_bytes = tx6.to_byte_array();

        let real_merkleroot_str =
            "3d0b734737057e5345df12c126caed936081d1af89b96731c1d83e295c504310";
        let real_merkleroot = sha256d::Hash::from_str(real_merkleroot_str).unwrap();
        let real_merkleroot_bytes = real_merkleroot.to_byte_array();

        let merkletree = MerkleTree::from_txs(&[
            tx1_bytes, tx2_bytes, tx3_bytes, tx4_bytes, tx5_bytes, tx6_bytes,
        ])
        .unwrap();

        assert!(merkletree.verify_merkle_root(real_merkleroot_bytes));
    }

    /*
                        ABCDEFGHIJKLIJKL
                ABCDEFGH                IJKLIJKL
            ABCD        EFGH          IJKL
          AB    CD    EF    GH      IJ    KL
         A  B  C  D  E  F  G  H    I  J  K  L
    */
    #[test]
    fn test_12_txs() {
        let tx1_str = "a69ffbd48b6c3f87541021bf95261ffadcd079ceca5ec8619c5e41c97a86083b";
        let tx1 = sha256d::Hash::from_str(tx1_str).unwrap();
        let tx1_bytes = tx1.to_byte_array();

        let tx2_str = "9f221665fd0f30c9ec72040fea80afb504cda5965c838ad83540b64572223c05";
        let tx2 = sha256d::Hash::from_str(tx2_str).unwrap();
        let tx2_bytes = tx2.to_byte_array();

        let tx3_str = "ea41700bc62fc1aa6e865fc85540cfd03e805a633c05a9cf13d017b10859ccba";
        let tx3 = sha256d::Hash::from_str(tx3_str).unwrap();
        let tx3_bytes = tx3.to_byte_array();

        let tx4_str = "4669023df0d54f4cf2928ab76dd3d863923fb654adff077e451c30d9e8fa3818";
        let tx4 = sha256d::Hash::from_str(tx4_str).unwrap();
        let tx4_bytes = tx4.to_byte_array();

        let tx5_str = "cba7e7cc419db453dd115f337610f06ee02714455f7015a86944f8066f1d620e";
        let tx5 = sha256d::Hash::from_str(tx5_str).unwrap();
        let tx5_bytes = tx5.to_byte_array();

        let tx6_str = "3b44d36b1377d86b657ac23eec68aec14990943404d3919dafd376d43672e402";
        let tx6 = sha256d::Hash::from_str(tx6_str).unwrap();
        let tx6_bytes = tx6.to_byte_array();

        let tx7_str = "0526d6c824ccff6f0096856cf3144a4a36c75e3cfea509940c5065e209db9750";
        let tx7 = sha256d::Hash::from_str(tx7_str).unwrap();
        let tx7_bytes = tx7.to_byte_array();

        let tx8_str = "384671743f55a9f14a9fb76af8252bb8d0ec177c840c80e751479fb0bcc751c7";
        let tx8 = sha256d::Hash::from_str(tx8_str).unwrap();
        let tx8_bytes = tx8.to_byte_array();

        let tx9_str = "b26481ec45727e5b80b8e9d6cc83c40a6e15265300bf59f1670acce80bb4ec98";
        let tx9 = sha256d::Hash::from_str(tx9_str).unwrap();
        let tx9_bytes = tx9.to_byte_array();

        let tx10_str = "e554d2739e5085ab2ba913c8c4b4c25cd58c097d0db54d4413f2eab950e45f37";
        let tx10 = sha256d::Hash::from_str(tx10_str).unwrap();
        let tx10_bytes = tx10.to_byte_array();

        let tx11_str = "8b19de2040c99c253e71fa1e99885c8495d09aa279e05c7f731b0e7ceecfda61";
        let tx11 = sha256d::Hash::from_str(tx11_str).unwrap();
        let tx11_bytes = tx11.to_byte_array();

        let tx12_str = "291de5367ddc95e68b8bc19c2c2812045c1b5c999f5bb90196f753fe758003a0";
        let tx12 = sha256d::Hash::from_str(tx12_str).unwrap();
        let tx12_bytes = tx12.to_byte_array();

        let real_merkleroot_str =
            "1978672df47b2d1701f344c36977a3101b879df6c681bba2b7be9686521dde8f";
        let real_merkleroot = sha256d::Hash::from_str(real_merkleroot_str).unwrap();
        let real_merkleroot_bytes = real_merkleroot.to_byte_array();

        let txs_bytes = vec![
            tx1_bytes, tx2_bytes, tx3_bytes, tx4_bytes, tx5_bytes, tx6_bytes, tx7_bytes, tx8_bytes,
            tx9_bytes, tx10_bytes, tx11_bytes, tx12_bytes,
        ];
        let merkletree = MerkleTree::from_txs(&txs_bytes).unwrap();

        assert!(merkletree.verify_merkle_root(real_merkleroot_bytes));
    }
}
