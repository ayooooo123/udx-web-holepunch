'use strict'

const test = require('brittle')
const HyperDHT = require('hyperdht')
const NoiseSecretStream = require('@hyperswarm/secret-stream')
const b4a = require('b4a')
const { WebBridgeUDX, BrowserUDX } = require('../index')

test('direct C libudx <-> BrowserUDXStream (0xff 0x01 wire frames + Noise SecretStream on single UDP port)', async (t) => {
  const nativeUdx = new WebBridgeUDX()
  const browserUdx = new BrowserUDX()

  const nativeSocket = nativeUdx.createSocket()
  nativeSocket.bind(0, '127.0.0.1')
  const nativePort = nativeSocket.address().port

  const browserSocket = browserUdx.createSocket()
  browserSocket.bind(0, '127.0.0.1')

  const nativeStreamId = 101
  const browserStreamId = 202

  const nativeStream = nativeUdx.createStream(nativeStreamId, {
    framed: true,
    firewall (sock, port, host) {
      nativeStream.connect(sock, browserStreamId, port, host)
      return false
    }
  })

  const browserStream = browserUdx.createStream(browserStreamId, {
    framed: true
  })
  browserStream.connect(browserSocket, nativeStreamId, nativePort, '127.0.0.1')

  const serverNoise = new NoiseSecretStream(false, nativeStream)
  const clientNoise = new NoiseSecretStream(true, browserStream)
  serverNoise.on('error', () => {})
  clientNoise.on('error', () => {})

  const receivedByServer = new Promise((resolve) => {
    serverNoise.once('data', (chunk) => {
      resolve(b4a.toString(chunk))
      serverNoise.write(b4a.from('pong-from-native-c-libudx'))
    })
  })

  const receivedByBrowser = new Promise((resolve) => {
    clientNoise.once('data', (chunk) => {
      resolve(b4a.toString(chunk))
    })
  })

  clientNoise.write(b4a.from('ping-from-browser-udx'))

  const msg1 = await receivedByServer
  const msg2 = await receivedByBrowser

  t.is(msg1, 'ping-from-browser-udx', 'native C libudx parsed 0xff 0x01 UDX + Noise frame from browser')
  t.is(msg2, 'pong-from-native-c-libudx', 'browser parsed 0xff 0x01 UDX + Noise frame from native C libudx')
  t.ok(nativeStream.packetsReceived > 0, 'native C libudx recorded real UDX packets received')
  t.ok(nativeStream.packetsTransmitted > 0, 'native C libudx recorded real UDX packets transmitted')

  clientNoise.destroy()
  serverNoise.destroy()
  await browserUdx.destroy()
  await browserSocket.close()
  await nativeSocket.close()
})

test('full HyperDHT cold bootstrap + bidirectional Holepuncher (Browser <-> Firewalled Native Peers)', async (t) => {
  // Spin up 4 DHT routing nodes with WebBridgeUDX (>=3 required by hyperdht Nat.autoSample for FIREWALL.CONSISTENT)
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

  // 1. Firewalled native HyperDHT server dialed by firewalled Browser HyperDHT client
  const nativeServerDht = new HyperDHT({
    udx: new WebBridgeUDX(),
    bootstrap,
    ephemeral: true,
    firewalled: true,
    host: '127.0.0.1'
  })
  await nativeServerDht.fullyBootstrapped()

  const serverKeyPair = HyperDHT.keyPair()
  let serverConnResolve
  const serverConnPromise = new Promise((resolve) => {
    serverConnResolve = resolve
  })

  const server = nativeServerDht.createServer({ shareLocalAddress: false }, (conn) => {
    conn.on('error', () => {})
    conn.once('data', (data) => {
      const text = b4a.toString(data)
      conn.write(b4a.from(`echo:${text}`))
      serverConnResolve({
        text,
        remotePublicKey: conn.remotePublicKey,
        packetsReceived: conn.rawStream.packetsReceived
      })
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

  const clientConn = browserDht.connect(serverKeyPair.publicKey, {
    localConnection: false,
    fastOpen: false
  })
  clientConn.on('error', () => {})

  const browserGotEcho = new Promise((resolve, reject) => {
    clientConn.once('error', reject)
    clientConn.once('open', () => {
      clientConn.write(b4a.from('holepunched-udx-payload'))
    })
    clientConn.once('data', (data) => {
      resolve(b4a.toString(data))
    })
  })

  const [serverResult, echoReply] = await Promise.all([
    serverConnPromise,
    browserGotEcho
  ])

  t.is(serverResult.text, 'holepunched-udx-payload', 'firewalled native server received payload after holepunch')
  t.is(echoReply, 'echo:holepunched-udx-payload', 'browser received echoed payload over UDX stream')
  t.alike(serverResult.remotePublicKey, browserDht.defaultKeyPair.publicKey, 'Noise XX verified browser Ed25519 identity')
  t.ok(serverResult.packetsReceived > 0, 'native C libudx processed real 0xff 0x01 UDX frames on the holepunched socket')
  t.ok(
    nativeServerDht.stats.punches.consistent >= 1 && browserDht.stats.punches.consistent >= 1,
    `both sides executed consistent UDP NAT holepunch (server=${nativeServerDht.stats.punches.consistent}, browser=${browserDht.stats.punches.consistent})`
  )

  // 2. Reverse direction: Firewalled Browser HyperDHT server dialed by Firewalled Native HyperDHT client
  const browserServerKeyPair = HyperDHT.keyPair()
  let browserServerResolve
  const browserServerPromise = new Promise((resolve) => {
    browserServerResolve = resolve
  })

  const browserServer = browserDht.createServer({ shareLocalAddress: false }, (conn) => {
    conn.on('error', () => {})
    conn.once('data', (data) => {
      const text = b4a.toString(data)
      conn.write(b4a.from(`browser-server-ack:${text}`))
      browserServerResolve({
        text,
        remotePublicKey: conn.remotePublicKey,
        packetsReceived: conn.rawStream.packetsReceived
      })
    })
  })
  await browserServer.listen(browserServerKeyPair)

  const nativeToBrowserConn = nativeServerDht.connect(browserServerKeyPair.publicKey, {
    localConnection: false,
    fastOpen: false
  })
  nativeToBrowserConn.on('error', () => {})

  const nativeGotAck = new Promise((resolve, reject) => {
    nativeToBrowserConn.once('error', reject)
    nativeToBrowserConn.once('open', () => {
      nativeToBrowserConn.write(b4a.from('native-dialing-browser'))
    })
    nativeToBrowserConn.once('data', (data) => {
      resolve(b4a.toString(data))
    })
  })

  const [browserServerRes, nativeAckReply] = await Promise.all([
    browserServerPromise,
    nativeGotAck
  ])

  t.is(browserServerRes.text, 'native-dialing-browser', 'firewalled browser server received payload from native peer after holepunch')
  t.is(nativeAckReply, 'browser-server-ack:native-dialing-browser', 'native peer received reply from browser server over C libudx')
  t.alike(browserServerRes.remotePublicKey, nativeServerDht.defaultKeyPair.publicKey, 'browser server verified native Ed25519 identity')
  t.ok(browserServerRes.packetsReceived > 0, 'BrowserUDXStream processed real 0xff 0x01 UDX frames from C libudx')

  nativeToBrowserConn.destroy()
  clientConn.destroy()
  await browserServer.close()
  await server.close()
  await browserDht.destroy()
  await browserUdx.destroy()
  await nativeServerDht.destroy()
  for (let i = dhtNodes.length - 1; i >= 0; i--) {
    await dhtNodes[i].destroy()
  }
})

test('2 BrowserUDX Hyperswarm + Protomux peers discover each other on a topic and chat P2P', async (t) => {
  const Hyperswarm = require('hyperswarm')
  const Protomux = require('protomux')
  const c = require('compact-encoding')

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

  const udxAlice = new BrowserUDX()
  const dhtAlice = new HyperDHT({ udx: udxAlice, bootstrap, ephemeral: true, firewalled: true, host: '127.0.0.1' })
  await dhtAlice.fullyBootstrapped()
  const swarmAlice = new Hyperswarm({ dht: dhtAlice, keyPair: dhtAlice.defaultKeyPair })

  const udxBob = new BrowserUDX()
  const dhtBob = new HyperDHT({ udx: udxBob, bootstrap, ephemeral: true, firewalled: true, host: '127.0.0.1' })
  await dhtBob.fullyBootstrapped()
  const swarmBob = new Hyperswarm({ dht: dhtBob, keyPair: dhtBob.defaultKeyPair })

  const topic = HyperDHT.hash(b4a.from('pear-browser-to-browser-test-room'))

  const bobReceived = new Promise((resolve) => {
    swarmBob.on('connection', (conn) => {
      conn.on('error', () => {})
      const mux = Protomux.from(conn)
      let msgType
      const ch = mux.createChannel({
        protocol: 'pear-p2p-chat',
        id: null
      })
      msgType = ch.addMessage({
        encoding: c.string,
        onmessage (str) {
          msgType.send(`bob-ack:${str}`)
          resolve(str)
        }
      })
      ch.open()
    })
  })

  const aliceReceived = new Promise((resolve) => {
    swarmAlice.on('connection', (conn) => {
      conn.on('error', () => {})
      const mux = Protomux.from(conn)
      let msgType
      const ch = mux.createChannel({
        protocol: 'pear-p2p-chat',
        id: null,
        onopen () {
          msgType.send('hello-from-alice-swarm')
        }
      })
      msgType = ch.addMessage({
        encoding: c.string,
        onmessage (str) {
          resolve(str)
        }
      })
      ch.open()
    })
  })

  const d1 = swarmAlice.join(topic, { client: true, server: true })
  await d1.flushed()
  const d2 = swarmBob.join(topic, { client: true, server: true })
  await d2.flushed()

  const [fromAlice, fromBob] = await Promise.all([bobReceived, aliceReceived])

  t.is(fromAlice, 'hello-from-alice-swarm', 'Bob browser peer received Protomux message over Hyperswarm + UDX')
  t.is(fromBob, 'bob-ack:hello-from-alice-swarm', 'Alice browser peer received Protomux reply from Bob')

  await swarmAlice.destroy()
  await swarmBob.destroy()
  await udxAlice.destroy()
  await udxBob.destroy()
  for (let i = dhtNodes.length - 1; i >= 0; i--) {
    await dhtNodes[i].destroy()
  }
})

test('BrowserUDX Hyperswarm peer connects to a 100% stock unmodified native Hyperswarm peer (no WebBridgeUDX on native peer)', async (t) => {
  const Hyperswarm = require('hyperswarm')
  const Protomux = require('protomux')
  const c = require('compact-encoding')

  const dhtNodes = []
  const bootstrap = []

  for (let i = 0; i < 4; i++) {
    // ONLY node 0 is a WebBridgeUDX entry node; nodes 1..3 are 100% stock unmodified HyperDHT nodes!
    const node = new HyperDHT({
      udx: i === 0 ? new WebBridgeUDX() : undefined,
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

  // 100% STOCK unmodified native Hyperswarm peer (uses default udx-native, NO WebBridgeUDX!)
  const stockNativeDht = new HyperDHT({
    bootstrap,
    ephemeral: true,
    firewalled: true,
    host: '127.0.0.1'
  })
  await stockNativeDht.fullyBootstrapped()
  const stockNativeSwarm = new Hyperswarm({
    dht: stockNativeDht,
    keyPair: stockNativeDht.defaultKeyPair
  })

  // Browser Hyperswarm peer using BrowserUDX
  const udxBrowser = new BrowserUDX()
  const dhtBrowser = new HyperDHT({
    udx: udxBrowser,
    bootstrap,
    ephemeral: true,
    firewalled: true,
    host: '127.0.0.1'
  })
  await dhtBrowser.fullyBootstrapped()
  const swarmBrowser = new Hyperswarm({
    dht: dhtBrowser,
    keyPair: dhtBrowser.defaultKeyPair
  })

  const topic = HyperDHT.hash(b4a.from('browser-to-stock-native-hyperswarm-room'))

  const stockNativeReceived = new Promise((resolve) => {
    stockNativeSwarm.on('connection', (conn) => {
      conn.on('error', () => {})
      const mux = Protomux.from(conn)
      let msgType
      const ch = mux.createChannel({
        protocol: 'pear-p2p-chat',
        id: null
      })
      msgType = ch.addMessage({
        encoding: c.string,
        onmessage (str) {
          msgType.send(`stock-native-reply:${str}`)
          resolve({ str, udxPacketsRx: conn.rawStream.packetsReceived })
        }
      })
      ch.open()
    })
  })

  const browserReceived = new Promise((resolve) => {
    swarmBrowser.on('connection', (conn) => {
      conn.on('error', () => {})
      const mux = Protomux.from(conn)
      let msgType
      const ch = mux.createChannel({
        protocol: 'pear-p2p-chat',
        id: null,
        onopen () {
          msgType.send('hello-stock-native-peer')
        }
      })
      msgType = ch.addMessage({
        encoding: c.string,
        onmessage (str) {
          resolve(str)
        }
      })
      ch.open()
    })
  })

  const d1 = stockNativeSwarm.join(topic, { client: true, server: true })
  await d1.flushed()
  const d2 = swarmBrowser.join(topic, { client: true, server: true })
  await d2.flushed()

  const [nativeRes, browserRes] = await Promise.all([stockNativeReceived, browserReceived])

  t.is(nativeRes.str, 'hello-stock-native-peer', '100% stock native Hyperswarm peer received message from browser')
  t.ok(nativeRes.udxPacketsRx > 0, 'stock udx-native C libudx received real 0xff 0x01 UDX packets from browser')
  t.is(browserRes, 'stock-native-reply:hello-stock-native-peer', 'browser received reply from stock native Hyperswarm peer')

  await swarmBrowser.destroy()
  await stockNativeSwarm.destroy()
  await udxBrowser.destroy()
  for (let i = dhtNodes.length - 1; i >= 0; i--) {
    await dhtNodes[i].destroy()
  }
})
