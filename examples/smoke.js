'use strict'

const HyperDHT = require('hyperdht')
const b4a = require('b4a')
const { WebBridgeUDX, BrowserUDX } = require('../index')

async function main () {
  const dhtNodes = []
  const bootstrap = []

  for (let i = 0; i < 4; i++) {
    const node = new HyperDHT({
      udx: new WebBridgeUDX(),
      ephemeral: false,
      firewalled: false,
      bootstrap,
      port: 0,
      host: '127.0.0.1'
    })
    await node.fullyBootstrapped()
    if (bootstrap.length === 0) {
      bootstrap.push({ host: '127.0.0.1', port: node.address().port })
    }
    dhtNodes.push(node)
  }

  const nativeDht = new HyperDHT({
    udx: new WebBridgeUDX(),
    bootstrap,
    ephemeral: true,
    firewalled: true,
    host: '127.0.0.1'
  })
  await nativeDht.fullyBootstrapped()

  const serverKeyPair = HyperDHT.keyPair()
  const server = nativeDht.createServer({ shareLocalAddress: false }, (conn) => {
    conn.on('data', (buf) => {
      console.log('[native-server] rx over C libudx:', b4a.toString(buf), '| udx packets rx:', conn.rawStream.packetsReceived)
      conn.write(b4a.from('cum-drenched-ack-from-native-udx'))
    })
  })
  await server.listen(serverKeyPair)

  const browserUdx = new BrowserUDX()
  const browserDht = new HyperDHT({
    udx: browserUdx,
    bootstrap,
    ephemeral: true,
    firewalled: true,
    host: '127.0.0.1'
  })
  await browserDht.fullyBootstrapped()

  const conn = browserDht.connect(serverKeyPair.publicKey, { localConnection: false })
  await new Promise((resolve, reject) => {
    conn.once('error', reject)
    conn.once('open', () => {
      conn.write(b4a.from('raw-0xff-udx-frame-from-browser'))
    })
    conn.once('data', (buf) => {
      console.log('[browser-client] rx over BrowserUDXStream:', b4a.toString(buf))
      console.log('[stats] consistent holepunches — native:', nativeDht.stats.punches.consistent, 'browser:', browserDht.stats.punches.consistent)
      resolve()
    })
  })

  conn.destroy()
  await server.close()
  await browserDht.destroy()
  await browserUdx.destroy()
  await nativeDht.destroy()
  for (let i = dhtNodes.length - 1; i >= 0; i--) {
    await dhtNodes[i].destroy()
  }
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
