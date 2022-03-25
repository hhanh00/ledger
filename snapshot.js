const Zemu = require('@zondax/zemu').default
const Resolve = require("path").resolve;

async function f() {
    const sim = new Zemu(Resolve('../ledger-zcash/app/output/app_s.elf'), {}, undefined, 9000, 9001)
    await sim.connect()
    const transport = await sim.getTransport()
    console.log(transport)
}

f()

