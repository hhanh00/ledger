use serde::{Serialize, Deserialize};

#[derive(Copy, Clone, Serialize, Deserialize, Debug)]
pub enum CoinType {
    Ycash, Zcash,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Tx {
    pub coin_type: CoinType,
    pub height: u32,
    pub t_inputs: Vec<TTxIn>,
    pub inputs: Vec<TxIn>,
    pub outputs: Vec<TxOut>,
    pub change: String,
    pub ovk: String,
}

impl Tx {
    pub fn new(coin_type: CoinType, height: u32) -> Self {
        Tx {
            coin_type,
            height,
            t_inputs: vec![],
            inputs: vec![],
            outputs: vec![],
            change: "".to_string(),
            ovk: "".to_string(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TxIn {
    pub diversifier: String,
    pub fvk: String,
    pub amount: u64,
    pub rseed: String,
    pub witness: String,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct TTxIn {
    pub op: String,
    pub n: u32,
    pub amount: u64,
    pub script: String,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct TxOut {
    pub addr: String,
    pub amount: u64,
    pub ovk: String,
    pub memo: String,
}
