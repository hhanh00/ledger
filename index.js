const Zemu = require('@zondax/zemu').default
const Resolve = require("path").resolve;

async function f() {
    const sim = new Zemu(Resolve('../ledger-zcash/app/output/app_s.elf'), {}, undefined, 9000, 9001)
    await sim.start({
        logging: true,
        custom: '-s "book pottery flame naive lend flock chase end pulp lawn lottery moon drive zebra join access capable taxi snap save resemble knife grit oblige"',
        startText: 'DO NOT USE!',
    })
    const transport = sim.getTransport()
    console.log(transport)
    for (var i = 0; i < 19; i++) {
        await sim.snapshot(`${i}.png`);
        await sim.waitScreenChange(100000);
        await sim.clickRight();
    }
    await sim.waitScreenChange(100000);
    await sim.clickBoth(); // approve
    for (var i = 0; i < 19; i++) {
        await sim.snapshot(`${i}.png`);
        await sim.waitScreenChange(100000);
        await sim.clickRight();
    }
}

f()
