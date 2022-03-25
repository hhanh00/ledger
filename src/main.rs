#![allow(unused_imports)]

use bip39::{Mnemonic, Language, Seed};
use byteorder::{ByteOrder, LE, LittleEndian, WriteBytesExt};
use ed25519_bip32::{DerivationScheme, XPrv};
use sha2::{Sha256, Sha512};
use hmac::{Hmac, Mac};
use hmac::digest::{crypto_common, FixedOutput, MacMarker, Update};
use blake2b_simd::Params;
use jubjub::Fr;
use ledger_apdu::{APDUAnswer, APDUCommand};
use zcash_primitives::zip32::{ExtendedSpendingKey, ChildIndex, ExtendedFullViewingKey, ChainCode, DiversifierKey, FvkFingerprint};
use zcash_client_backend::encoding::{decode_extended_full_viewing_key, decode_payment_address, encode_extended_spending_key, encode_payment_address};
use zcash_primitives::consensus::Network::MainNetwork;
use zcash_primitives::consensus::{Network, Parameters};
use zcash_primitives::constants::{PROOF_GENERATION_KEY_GENERATOR, SPENDING_KEY_GENERATOR};
use zcash_primitives::keys::OutgoingViewingKey;
use zcash_primitives::sapling::keys::{ExpandedSpendingKey, FullViewingKey};
use zcash_primitives::sapling::ViewingKey;
use serde::{Serialize, Deserialize};
use serde::__private::de::Content::ByteBuf;
use zcash_primitives::transaction::components::amount::DEFAULT_FEE;
use crate::tx::Tx;

// mod ledger;
mod tx;

const HARDENED: u32 = 0x8000_0000;
const NETWORK: &Network = &MainNetwork;

#[derive(Serialize, Deserialize)]
#[allow(non_snake_case)]
struct APDURequest {
    apduHex: String,
}

#[derive(Serialize, Deserialize)]
struct APDUReply {
    data: String,
    error: Option<String>,
}

// fn get_ivk(app: &LedgerApp) -> anyhow::Result<String> {
//     let command = ApduCommand {
//         cla: 0x85,
//         ins: 0xf0,
//         p1: 1,
//         p2: 0,
//         length: 4,
//         data: vec![0, 0, 0, 0]
//     };
//     let res = app.exchange(command)?;
//     let mut raw_ivk = [0u8; 32];
//     raw_ivk.copy_from_slice(&res.data);
//     let ivk = jubjub::Fr::from_bytes(&raw_ivk).unwrap();
//     let ivk = SaplingIvk(ivk);
//     let fvk = ExtendedFullViewingKey {
//         depth: 0,
//         parent_fvk_tag: (),
//         child_index: (),
//         chain_code: (),
//         fvk: FullViewingKey {},
//         dk: DiversifierKey()
//     };
//     println!("{}", address);
//
//     Ok(address)
// }

const CURVE_SEEDKEY: &[u8] = b"ed25519 seed";
const ZCASH_PERSO: &[u8] = b"Zcash_ExpandSeed";

type HMAC256 = Hmac<Sha256>;
type HMAC512 = Hmac<Sha512>;

fn hmac_sha2<T: Update + FixedOutput + MacMarker + crypto_common::KeyInit>(data: &mut [u8]) {
    let mut hmac = T::new_from_slice(CURVE_SEEDKEY).unwrap();
    hmac.update(&data);
    data.copy_from_slice(&hmac.finalize().into_bytes());
}

macro_rules! prf_expand {
    ($($y:expr),*) => (
    {
        let mut res = [0u8; 64];
        let mut hasher = Params::new()
            .hash_length(64)
            .personal(ZCASH_PERSO)
            .to_state();
        $(
            hasher.update($y);
        )*
        res.copy_from_slice(&hasher.finalize().as_bytes());
        res
    })
}

struct ExtSpendingKey {
    chain: [u8; 32],
    ovk: [u8; 32],
    dk: [u8; 32],
    ask: Fr,
    nsk: Fr,
}

fn derive_child(esk: &mut ExtSpendingKey, path: &[u32]) {
    let mut a = [0u8; 32];
    let mut n = [0u8; 32];
    a.copy_from_slice(&esk.ask.to_bytes());
    n.copy_from_slice(&esk.nsk.to_bytes());

    for &p in path {
        println!("==> ask: {}", hex::encode(esk.ask.to_bytes()));
        let hardened = (p & 0x8000_0000) != 0;
        let c = p & 0x7FFF_FFFF;
        assert!(hardened);
        //make index LE
        //zip32 child derivation
        let mut le_i = [0; 4];
        LittleEndian::write_u32(&mut le_i, c + (1 << 31));
        println!("==> chain: {}", hex::encode(esk.chain));
        println!("==> a: {}", hex::encode(a));
        println!("==> n: {}", hex::encode(n));
        println!("==> ovk: {}", hex::encode(esk.ovk));
        println!("==> dk: {}", hex::encode(esk.dk));
        println!("==> i: {}", hex::encode(le_i));
        let h = prf_expand!(&esk.chain, &[0x11], &a, &n, &esk.ovk, &esk.dk, &le_i);
        println!("==> tmp: {}", hex::encode(h));
        let mut key = [0u8; 32];
        key.copy_from_slice(&h[..32]);
        esk.chain.copy_from_slice(&h[32..]);
        let ask_cur = Fr::from_bytes_wide(&prf_expand!(&key, &[0x13]));
        let nsk_cur = Fr::from_bytes_wide(&prf_expand!(&key, &[0x14]));
        esk.ask += ask_cur;
        esk.nsk += nsk_cur;

        let t = prf_expand!(&key, &[0x15], &esk.ovk);
        esk.ovk.copy_from_slice(&t[..32]);
        let t = prf_expand!(&key, &[0x16], &esk.dk);
        esk.dk.copy_from_slice(&t[..32]);

        a.copy_from_slice(&scalar_to_bytes(&prf_expand!(&key, &[0x00])));
        n.copy_from_slice(&scalar_to_bytes(&prf_expand!(&key, &[0x01])));
    }
}

fn scalar_to_bytes(k: &[u8; 64]) -> [u8; 32] {
    let t = Fr::from_bytes_wide(k);
    t.to_bytes()
}

fn main() -> anyhow::Result<()> {
    dotenv::dotenv().unwrap();

    // let ledger = LedgerApp::new().unwrap();
    // info(&ledger).unwrap();

    // Convert mnemonic phrase to seed (BIP-39)
    let seed = dotenv::var("SEED").unwrap();
    let mnemonic = Mnemonic::from_phrase(&seed, Language::English)?;
    let seed = Seed::new(&mnemonic, "");
    let seed = seed.as_bytes();
    println!("{}", hex::encode(seed));

    // Derive using SLIP-10 (does not work because ledger-zcash uses BIP32-Ed25519
    // let path = BIP32Path::from_str("m/44'/133'/0'/0'/0'").unwrap();
    // let key = derive_key_from_path(&seed.as_bytes(), Curve::Ed25519, &path).unwrap();
    // println!("{}", hex::encode(&key.key));

    // ref: https://github.com/LedgerHQ/orakolo/blob/master/papers/Ed25519_BIP%20Final.pdf

    // Phase 1: Derive coin root key
    // Derive master root key
    let mut key = [0u8; 64];
    key.copy_from_slice(&seed);
    hmac_sha2::<HMAC512>(&mut key);

    while key[31] & 0x20 != 0 {
        hmac_sha2::<HMAC512>(&mut key);
    }
    key[0] &= 0xF8;
    key[31] &= 0x7F;
    key[31] |= 0x40;

    // Derive master chain code
    let mut chain_code = [0u8; 32];
    let mut hmac = HMAC256::new_from_slice(CURVE_SEEDKEY).unwrap();
    Mac::update(&mut hmac, &[1]);
    Mac::update(&mut hmac, &seed);
    chain_code.copy_from_slice(&hmac.finalize().into_bytes());

    // Derive using BIP-32/44 - path: m/44'/133'/0'/0'/0'
    let priv_key = XPrv::from_extended_and_chaincode(&key, &chain_code);
    let priv_key = priv_key.derive(DerivationScheme::V2, 0x8000002c);
    let priv_key = priv_key.derive(DerivationScheme::V2, 0x80000085);
    let priv_key = priv_key.derive(DerivationScheme::V2, 0x80000000);
    let priv_key = priv_key.derive(DerivationScheme::V2, 0x80000000);
    let priv_key = priv_key.derive(DerivationScheme::V2, 0x80000000);

    println!("BIP 32 - Ed25519: {}", hex::encode(priv_key.extended_secret_key()));

    // Phase 2: ZIP 32 - path: m/32'/133'/p'
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&priv_key.extended_secret_key()[0..32]);

    let master = ExtendedSpendingKey::master(&seed);
    let mut espk = ExtSpendingKey {
        chain: master.chain_code.0,
        ovk: master.expsk.ovk.0,
        dk: master.dk.0,
        ask: master.expsk.ask,
        nsk: master.expsk.nsk,
    };

    derive_child(&mut espk, &[HARDENED | 32, HARDENED | 133, HARDENED | 0]);
    let ak = SPENDING_KEY_GENERATOR * espk.ask;
    let nk = PROOF_GENERATION_KEY_GENERATOR * espk.nsk;
    let vk = ViewingKey {
        ak,
        nk,
    };
    let fvk = FullViewingKey {
        vk,
        ovk: OutgoingViewingKey(espk.ovk),
    };
    let tag = FvkFingerprint::from(&fvk).tag();

    let esk = ExpandedSpendingKey {
        ask: espk.ask,
        nsk: espk.nsk,
        ovk: OutgoingViewingKey(espk.ovk),
    };

    let sk = ExtendedSpendingKey {
        depth: 0,
        parent_fvk_tag: tag,
        child_index: ChildIndex::Hardened(0),
        chain_code: ChainCode(espk.chain),
        expsk: esk,
        dk: DiversifierKey(espk.dk),
    };

    // let path = [
    //     ChildIndex::Hardened(32),
    //     ChildIndex::Hardened(133),
    //     ChildIndex::Hardened(1000),
    // ];
    // let sk = ExtendedSpendingKey::from_path(&master, &path);

    let fvk = ExtendedFullViewingKey::from(&sk);
    let ivk = fvk.fvk.vk.ivk().0.to_bytes();
    println!("ivk: {}", hex::encode(&ivk));
    let nsk = sk.expsk.nsk;
    println!("nsk: {}", hex::encode(nsk.to_bytes()));
    let (_, pa) = sk.default_address();
    let address = encode_payment_address(NETWORK.hrp_sapling_payment_address(), &pa);
    println!("{}", address);

    let sk = encode_extended_spending_key(NETWORK.hrp_sapling_extended_spending_key(), &sk);
    println!("{}", sk);


    Ok(())
}

async fn make_tx_init_data(tx: &Tx) {
    let mut buffer = Vec::<u8>::new();
    let tin_count = tx.t_inputs.len();
    let s_in_count = tx.inputs.len();
    let s_out_count = tx.outputs.len();
    // TODO: Support t in/outputs
    assert_eq!(tin_count, 0);
    buffer.push(0u8);
    buffer.push(0u8);
    // buffer.push(0u8);
    // buffer.push(0u8);
    buffer.push(s_in_count as u8);
    buffer.push((s_out_count + 1) as u8); // +1 for change

    let mut change = 0;
    for sin in tx.inputs.iter() {
        buffer.write_u32::<LE>(0).unwrap();
        let fvk = decode_extended_full_viewing_key(NETWORK.hrp_sapling_extended_full_viewing_key(), &sin.fvk).unwrap().unwrap();
        let (_, pa) = fvk.default_address();
        let address = encode_payment_address(NETWORK.hrp_sapling_payment_address(), &pa);
        assert_eq!(address, "zs1m8d7506t4rpcgaag392xae698gx8j5at63qpg54ssprg6eqej0grmkfu76tq6p495z3w6s8qlll");
        assert_eq!(pa.to_bytes().len(), 43);
        buffer.extend_from_slice(&pa.to_bytes());
        buffer.write_u64::<LE>(sin.amount).unwrap();
        change += sin.amount as i64;
    }

    // assert_eq!(buffer.len(), 4+55*s_in_count);

    for sout in tx.outputs.iter() {
        println!("{} {}", buffer.len(), sout.addr);
        let pa = decode_payment_address(NETWORK.hrp_sapling_payment_address(), &sout.addr).unwrap().unwrap();
        assert_eq!(pa.to_bytes().len(), 43);
        buffer.extend_from_slice(&pa.to_bytes());
        println!("{}", buffer.len());
        buffer.write_u64::<LE>(sout.amount).unwrap();
        println!("{}", buffer.len());
        buffer.push(0xF6); // no memo
        println!("{}", buffer.len());
        buffer.push(0x01); // ovk present
        buffer.extend_from_slice(&hex::decode(&sout.ovk).unwrap());
        println!("{}", buffer.len());
        change -= sout.amount as i64;
    }
    assert_eq!(buffer.len(), 4+55*s_in_count+85*(s_out_count));

    change -= i64::from(DEFAULT_FEE);
    assert!(change >= 0);

    let pa_change = decode_payment_address(NETWORK.hrp_sapling_payment_address(), &tx.change).unwrap().unwrap();
    buffer.extend_from_slice(&pa_change.to_bytes());
    buffer.write_u64::<LE>(change as u64).unwrap();
    buffer.push(0xF6); // no memo
    buffer.push(0x01); // ovk present
    buffer.extend_from_slice(&hex::decode(&tx.ovk).unwrap());

    assert_eq!(buffer.len(), 4+55*s_in_count+85*(s_out_count+1));
    println!("txlen {}", buffer.len());

    let mut chunks: Vec<_> = buffer.chunks(250).collect();
    chunks.insert(0, &[]); // starts with empty chunk
    for (index, c) in chunks.iter().enumerate() {
        let p1 = match index {
            0 => 0,
            _ if index == chunks.len() - 1 => 2,
            _ => 1,
        };
        println!("data {}", hex::encode(c));
        let command = APDUCommand {
            cla: 0x85,
            ins: 0xA0,
            p1,
            p2: 0,
            data: c.to_vec(),
        };
        let rep = send_request(&command).await;
        println!("{}", rep.retcode);
    }

    // get spend data
    for _ in 0..s_in_count {
        let command = APDUCommand {
            cla: 0x85,
            ins: 0xA1,
            p1: 0,
            p2: 0,
            data: vec![],
        };
        let rep = send_request(&command).await;
        println!("{}", rep.retcode);
        let ak = &rep.data[0..32];
        let nsk = &rep.data[32..64];
        let rcv = &rep.data[64..96];
        let alpha = &rep.data[96..128];
        println!("ak {}", hex::encode(ak));
        println!("nsk {}", hex::encode(nsk));
        println!("rcv {}", hex::encode(rcv));
        println!("alpha {}", hex::encode(alpha));
    }
}

async fn send_request(command: &APDUCommand) -> APDUAnswer {
    let port = 9000;
    let apdu_hex = hex::encode(command.serialize());
    let client = reqwest::Client::new();
    let rep = client.post(format!("http://127.0.0.1:{}", port)).json(&APDURequest {
        apduHex: apdu_hex,
    }).header("Content-Type", "application/json").send().await.unwrap();
    let rep: APDUReply = rep.json().await.unwrap();
    let answer = APDUAnswer::from_answer(hex::decode(rep.data).unwrap());
    answer
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::Read;
    use ledger_apdu::*;
    use crate::{APDUReply, APDURequest, make_tx_init_data, send_request};
    use crate::tx::Tx;

    #[tokio::test]
    async fn get_version() {
        let command = APDUCommand {
            cla: 0x85,
            ins: 0x00,
            p1: 0,
            p2: 0,
            data: vec![],
        };
        let answer = send_request(&command).await;
        assert_eq!(answer.retcode, 0x9000);
        println!("{}.{}", answer.data[1], answer.data[2]);
        assert_eq!(answer.data[1], 3);
    }

    #[tokio::test]
    async fn get_addr() {
        let command = APDUCommand {
            cla: 0x85,
            ins: 0x11,
            p1: 0,
            p2: 0,
            data: vec![0, 0, 0, 0],
        };
        let answer = send_request(&command).await;
        let address = String::from_utf8(answer.data[43..].to_ascii_lowercase()).unwrap();
        println!("{}", address);
        assert_eq!(address, "zs1m8d7506t4rpcgaag392xae698gx8j5at63qpg54ssprg6eqej0grmkfu76tq6p495z3w6s8qlll");
    }

    #[tokio::test]
    async fn load_tx() {
        let file = File::open("tx.json").unwrap();
        let tx: Tx = serde_json::from_reader(&file).unwrap();
        make_tx_init_data(&tx).await;
    }
}

