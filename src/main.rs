use ledger::{LedgerApp, ApduCommand};
use bip39::{Mnemonic, Language, Seed};
use ed25519_bip32::{DerivationScheme, XPrv};
use sha2::{Sha256, Sha512};
use hmac::{Hmac, Mac};
use hmac::digest::{crypto_common, FixedOutput, MacMarker, Update};
use zcash_primitives::zip32::{ExtendedSpendingKey, ChildIndex, ExtendedFullViewingKey};
use zcash_client_backend::encoding::encode_payment_address;
use zcash_primitives::consensus::Network::MainNetwork;
use zcash_primitives::consensus::Parameters;
use zcash_primitives::sapling::keys::FullViewingKey;

#[allow(dead_code)]
fn info(app: &LedgerApp) -> anyhow::Result<()> {
    let command = ApduCommand {
        cla: 0x85,
        ins: 0x00,
        p1: 0,
        p2: 0,
        length: 0,
        data: vec![]
    };
    let res = app.exchange(command)?;
    println!("{}", hex::encode(res.data));

    Ok(())
}

fn get_addr(app: &LedgerApp) -> anyhow::Result<String> {
    let command = ApduCommand {
        cla: 0x85,
        ins: 0x11,
        p1: 0,
        p2: 0,
        length: 4,
        data: vec![0, 0, 0, 0]
    };
    let res = app.exchange(command)?;
    let address = String::from_utf8(res.data[43..].to_ascii_lowercase())?;
    println!("{}", address);

    Ok(address)
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
type HMAC256 = Hmac<Sha256>;
type HMAC512 = Hmac<Sha512>;

fn hmac_sha2<T: Update + FixedOutput + MacMarker + crypto_common::KeyInit>(data: &mut [u8]) {
    let mut hmac = T::new_from_slice(CURVE_SEEDKEY).unwrap();
    hmac.update(&data);
    data.copy_from_slice(&hmac.finalize().into_bytes());
}

fn main() -> anyhow::Result<()> {
    dotenv::dotenv().unwrap();

    let ledger = LedgerApp::new().unwrap();
    info(&ledger).unwrap();

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
    let path = [
        ChildIndex::Hardened(32),
        ChildIndex::Hardened(133),
        ChildIndex::Hardened(1000),
    ];
    let sk = ExtendedSpendingKey::from_path(&master, &path);

    // let fvk = ExtendedFullViewingKey::from(&sk);
    // let ivk = fvk.fvk.vk.ivk().0.to_bytes();
    // println!("ivk: {}", hex::encode(&ivk));
    // let nsk = sk.expsk.nsk;
    // println!("nsk: {}", hex::encode(nsk.to_bytes()));
    let (_, pa) = sk.default_address();
    let address = encode_payment_address(MainNetwork.hrp_sapling_payment_address(), &pa);
    println!("{}", address);

    Ok(())
}

