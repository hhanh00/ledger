use ledger::{LedgerApp, ApduCommand};

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

