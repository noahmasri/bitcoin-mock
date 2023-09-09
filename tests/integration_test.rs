#[cfg(test)]
use bitcoin_hashes::{sha256d, Hash};
use chrono::NaiveDate;
use std::fs::File;
use std::net::{IpAddr, Ipv4Addr};
use tp_bitcoins::server::{
    blockdownload::Blockchain,
    blocks::Block,
    handshake::{get_ips_address, handshakes},
    merkletree::MerkleTree,
};
use tp_bitcoins::utils::errors::{DownloadError, MessageError};

#[test]
fn test_merkle_tree_validate_blocks() -> Result<(), MessageError> {
    for i in 1..5 {
        let mut block =
            Block::parse_blocks_message(&mut File::open(format!("tests/some_blocks/block{}", i))?)?;
        let mut txs_hashes = vec![];
        txs_hashes.push(sha256d::Hash::hash(&block.coinbase_tx.as_bytes()).to_byte_array());

        for tx in &mut block.txs {
            let tx_bytes = tx.as_bytes();
            txs_hashes.push(sha256d::Hash::hash(&tx_bytes).to_byte_array());
        }

        let block_merkle_root = block.header.merkle_root;
        match MerkleTree::from_txs(&txs_hashes.clone()) {
            Ok(merkletree) => assert!(merkletree.verify_merkle_root(block_merkle_root)),
            Err(e) => {
                println!("Error {:?}", e);
                panic!();
            }
        }
    }

    Ok(())
}

#[test]
fn can_receive_blocks_messages() -> Result<(), DownloadError> {
    let addresses = get_ips_address("seed.testnet.bitcoin.sprovoost.nl", 18333)?;
    let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    let port = 1001;
    let nodes = handshakes(70015, (ip, port), 0, addresses, None)?;
    if let Some(start_date) = NaiveDate::from_ymd_opt(2023, 7, 12) {
        let blockchain =
            Blockchain::initial_block_download(&nodes, start_date, "headers.bin", "blocks", None)?;
        assert_eq!(
            blockchain.block_headers.list[blockchain.first_block_index..].len(),
            blockchain.blocks.len()
        );
    } else {
        panic!();
    }

    Ok(())
}

#[test]
fn blocks_gotten_are_ordered_by_timestamp() -> Result<(), DownloadError> {
    let addresses = get_ips_address("seed.testnet.bitcoin.sprovoost.nl", 18333)?;
    let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    let port = 1001;
    let nodes = handshakes(70015, (ip, port), 0, addresses, None)?;

    if let Some(start_date) = NaiveDate::from_ymd_opt(2023, 7, 10) {
        println!("handshake done");
        let blockchain =
            Blockchain::initial_block_download(&nodes, start_date, "headers.bin", "blocks", None)?;
        assert_eq!(
            blockchain.blocks.len(),
            blockchain.block_headers.list[blockchain.first_block_index..].len()
        );
        let mut prev_height = 0;
        for head in blockchain.block_headers.list[blockchain.first_block_index..].iter() {
            if let Some(curr) = blockchain.blocks.get(&head.hash()) {
                assert!(prev_height <= curr.height());
                prev_height = curr.height();
            }
        }
    } else {
        panic!();
    }

    Ok(())
}
