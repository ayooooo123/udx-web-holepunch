import HyperDHT from '../node_modules/hyperdht/index.js'
import b4a from 'b4a'
import BrowserUDX from '../lib/browser-udx.js'

// Expose the full HyperDHT + BrowserUDX stack on window so the real browser webpage can holepunch P2P
window.HyperDHT = HyperDHT
window.BrowserUDX = BrowserUDX
window.b4a = b4a

window.runBrowserDhtSuite = async function ({ bootstrap, serverPublicKeyHex }) {
  const logs = []
  const log = (msg) => {
    logs.push(msg)
    const el = document.getElementById('out')
    if (el) el.textContent = logs.join('\n')
    console.log(msg)
  }

  log(`[browser] cold-bootstrapping HyperDHT to ${JSON.stringify(bootstrap)} (0 signaling servers)...`)
  const browserUdx = new BrowserUDX()
  const dht = new HyperDHT({
    udx: browserUdx,
    bootstrap,
    ephemeral: true,
    firewalled: true,
    host: '127.0.0.1'
  })

  await dht.fullyBootstrapped()
  log('[browser] DHT fullyBootstrapped! Initiating P2P holepunch to firewalled native server...')

  // 1. Browser Client -> Firewalled Native Server over holepunched UDX + Noise XX
  const remotePubKey = b4a.from(serverPublicKeyHex, 'hex')
  const conn = dht.connect(remotePubKey, {
    localConnection: false,
    fastOpen: false
  })
  conn.on('error', () => {})

  const echoResult = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('Timeout waiting for holepunched UDX echo')), 15000)
    conn.once('error', (err) => {
      clearTimeout(timer)
      reject(err)
    })
    conn.once('open', () => {
      log('[browser] Noise SecretStream OPEN over UDX! Sending payload...')
      conn.write(b4a.from('real-browser-webrtc-udx-frame'))
    })
    conn.once('data', (data) => {
      clearTimeout(timer)
      const text = b4a.toString(data)
      log(`[browser] Received over BrowserUDXStream: ${text}`)
      resolve({
        echo: text,
        udxPacketsRx: conn.rawStream.packetsReceived,
        udxPacketsTx: conn.rawStream.packetsTransmitted,
        consistentPunches: dht.stats.punches.consistent
      })
    })
  })

  // 2. Host a Firewalled Browser HyperDHT Server inside the webpage and let Native dial it!
  const browserServerKeyPair = HyperDHT.keyPair()
  let incomingFromNativeResolve
  const incomingFromNativePromise = new Promise((resolve) => {
    incomingFromNativeResolve = resolve
  })

  const browserServer = dht.createServer({ shareLocalAddress: false }, (incomingConn) => {
    incomingConn.on('error', () => {})
    incomingConn.once('data', (data) => {
      const text = b4a.toString(data)
      log(`[browser-server] Received from native client: ${text}`)
      incomingConn.write(b4a.from(`browser-server-echo:${text}`))
      incomingFromNativeResolve({
        receivedText: text,
        remotePublicKeyHex: b4a.toString(incomingConn.remotePublicKey, 'hex'),
        udxPacketsRx: incomingConn.rawStream.packetsReceived
      })
    })
  })

  await browserServer.listen(browserServerKeyPair)
  const browserServerPubKeyHex = b4a.toString(browserServerKeyPair.publicKey, 'hex')
  log(`[browser-server] Listening on DHT key ${browserServerPubKeyHex}`)

  window.__finishBrowserSuite = async () => {
    const incomingRes = await incomingFromNativePromise
    conn.destroy()
    await browserServer.close()
    await dht.destroy()
    await browserUdx.destroy()
    return {
      clientToNative: echoResult,
      nativeToBrowserServer: incomingRes,
      browserPublicKeyHex: b4a.toString(dht.defaultKeyPair.publicKey, 'hex')
    }
  }

  return {
    clientToNative: echoResult,
    browserServerPubKeyHex,
    browserPublicKeyHex: b4a.toString(dht.defaultKeyPair.publicKey, 'hex')
  }
}
