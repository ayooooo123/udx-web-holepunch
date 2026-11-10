// Browser setTimeout/setInterval return numeric IDs; polyfill .unref()/.ref() so hyperdht timers never throw
if (typeof Number.prototype.unref !== 'function') {
  // eslint-disable-next-line no-extend-native
  Object.defineProperty(Number.prototype, 'unref', {
    value: function () { return this },
    configurable: true
  })
  // eslint-disable-next-line no-extend-native
  Object.defineProperty(Number.prototype, 'ref', {
    value: function () { return this },
    configurable: true
  })
}

'use strict'

const { EventEmitter } = require('events')
const streamx = require('streamx')
const b4a = require('b4a')
const {
  VPORT_MAGIC,
  PEER_ENVELOPE_MAGIC,
  WEBRTC_SIGNAL_MAGIC,
  TYPE,
  buildPacket,
  parsePacket,
  isStunPacket,
  isDtlsPacket,
  isUdxPacket
} = require('./wire')
const {
  DEFAULT_ICE_UFRAG,
  DEFAULT_ICE_PWD,
  DEFAULT_CERT,
  buildIceLiteSdp
} = require('./cert')

const DEFAULT_RWND = 262144
const MAX_PAYLOAD = 1100

const DEFAULT_ICE_SERVERS = [
  { urls: ['stun:stun.cloudflare.com:3478', 'stun:stun.l.google.com:19302'] }
]

// Zero-dependency Node UDP client speaking STUN + DTLS 1.2 + SCTP when window.RTCPeerConnection is absent
class NodeUdpWebRtcLink {
  constructor (udx, host, port, onOpen, onMessage) {
    const nodeReq = eval('require')
    const dgram = nodeReq('dgram')
    const { BINDING_RESPONSE, parseStun, buildBindingRequest } = nodeReq('./stun')
    const { DtlsEndpoint } = nodeReq('./dtls')
    const { SctpEndpoint } = nodeReq('./sctp')

    this.udx = udx
    this.host = host
    this.port = port
    this.onOpen = onOpen
    this.onMessage = onMessage
    this.closed = false
    this.stunVerified = false

    this.udp = dgram.createSocket('udp4')
    if (this.udp.unref) this.udp.unref()

    this.dtls = new DtlsEndpoint({
      role: 'client',
      cert: DEFAULT_CERT,
      send: (pkt) => {
        if (!this.closed) this.udp.send(pkt, this.port, this.host)
      }
    })

    this.sctp = new SctpEndpoint({
      role: 'client',
      port: 5000,
      send: (pkt) => {
        this.dtls.send(pkt)
      }
    })

    this.dtls.on('connect', () => {
      if (!this.closed) this.sctp.startClient()
    })

    this.dtls.on('data', (pkt) => {
      if (!this.closed) this.sctp.feedPacket(pkt)
    })

    this.sctp.on('open', () => {
      if (!this.closed) this.onOpen()
    })

    this.sctp.on('message', (buf) => {
      if (!this.closed) this.onMessage(buf)
    })

    this.udp.on('message', (msg) => {
      if (this.closed) return
      if (isStunPacket(msg)) {
        const parsed = parseStun(msg)
        if (parsed && parsed.type === BINDING_RESPONSE && !this.stunVerified) {
          this.stunVerified = true
          this.dtls.startClient()
        }
        return
      }
      if (isDtlsPacket(msg)) {
        this.dtls.feedPacket(msg)
      }
    })

    this.udp.bind(0, '127.0.0.1', () => {
      if (this.closed) return
      const stunReq = buildBindingRequest({
        localUfrag: 'nodeclient',
        remoteUfrag: this.udx.iceUfrag,
        remotePwd: this.udx.icePwd
      })
      this.udp.send(stunReq, this.port, this.host)
    })
  }

  send (buf) {
    if (!this.closed) this.sctp.sendData(buf, 0)
  }

  async close () {
    if (this.closed) return
    this.closed = true
    this.sctp.close()
    this.dtls.close()
    await new Promise((resolve) => {
      try {
        this.udp.close(() => resolve())
      } catch {
        resolve()
      }
    })
  }
}

// One WebRTC DataChannel tunnel to a native peer's UDP port OR upgraded direct browser-to-browser P2P link
class BrowserPeerLink {
  constructor (udx, host, port) {
    this.udx = udx
    this.host = host
    this.port = port
    this.key = `${host}:${port}`
    this.lastSourcePort = 0
    this.open = false
    this.isDirectP2P = false
    this.closed = false
    this.queue = []
    this._nodeLink = null
    this.pc = null
    this.dc = null
    this.directPc = null
    this.directDc = null
    this._directNegotiationStarted = false
    this._pendingRemoteCandidates = []

    const PeerConnection = udx.RTCPeerConnection
    if (PeerConnection) {
      this.pc = new PeerConnection()
      this.dc = this.pc.createDataChannel('udx', {
        ordered: false,
        maxRetransmits: 0,
        negotiated: true,
        id: 0
      })
      this.dc.binaryType = 'arraybuffer'
      this.dc.onopen = () => this._onOpen()
      this.dc.onmessage = (ev) => {
        const data =
          ev.data instanceof ArrayBuffer
            ? new Uint8Array(ev.data)
            : b4a.from(ev.data)
        this._onMessage(b4a.from(data))
      }
      this._connectBrowserPc().catch(() => {})
    } else {
      this._nodeLink = new NodeUdpWebRtcLink(
        udx,
        host,
        port,
        () => this._onOpen(),
        (buf) => this._onMessage(b4a.from(buf))
      )
    }
  }

  async _connectBrowserPc () {
    const offer = await this.pc.createOffer()
    await this.pc.setLocalDescription(offer)
    if (this.closed) return

    const midMatch = offer.sdp && offer.sdp.match(/a=mid:([^\r\n]+)/)
    const mid = midMatch ? midMatch[1].trim() : '0'

    const sdp = buildIceLiteSdp({
      host: this.host,
      port: this.port,
      fingerprint: this.udx.fingerprint,
      ufrag: this.udx.iceUfrag,
      pwd: this.udx.icePwd,
      mid
    })

    await this.pc.setRemoteDescription({ type: 'answer', sdp })
  }

  // Initiate a direct browser-to-browser RTCPeerConnection with STUN srflx candidates for cross-network punching
  async _startDirectP2POffer (sourcePort) {
    if (this._directNegotiationStarted || this.closed || !this.udx.RTCPeerConnection) return
    this._directNegotiationStarted = true
    const PeerConnection = this.udx.RTCPeerConnection
    this.directPc = new PeerConnection({ iceServers: this.udx.iceServers })

    this.directPc.onicecandidate = (ev) => {
      if (ev.candidate && !this.closed) {
        this._sendSignal({ type: 'candidate', candidate: ev.candidate }, sourcePort)
      }
    }

    const dc = this.directPc.createDataChannel('udx-direct-p2p', {
      ordered: false,
      maxRetransmits: 0
    })
    this._bindDirectDataChannel(dc)

    const offer = await this.directPc.createOffer()
    await this.directPc.setLocalDescription(offer)
    if (this.closed) return

    this._sendSignal({ type: 'offer', sdp: offer }, sourcePort)
  }

  async _handleSignal (signal, localPort) {
    if (this.closed || !this.udx.RTCPeerConnection) return
    const PeerConnection = this.udx.RTCPeerConnection

    if (signal.type === 'offer') {
      if (this.directPc && this.directPc.signalingState !== 'stable') {
        if (localPort < this.port) return
        try { this.directPc.close() } catch {}
        this.directPc = null
      }
      this._directNegotiationStarted = true
      if (!this.directPc) {
        this.directPc = new PeerConnection({ iceServers: this.udx.iceServers })
        this.directPc.onicecandidate = (ev) => {
          if (ev.candidate && !this.closed) {
            this._sendSignal({ type: 'candidate', candidate: ev.candidate }, localPort)
          }
        }
        this.directPc.ondatachannel = (ev) => {
          this._bindDirectDataChannel(ev.channel)
        }
      }
      await this.directPc.setRemoteDescription(signal.sdp)
      while (this._pendingRemoteCandidates.length > 0) {
        const c = this._pendingRemoteCandidates.shift()
        await this.directPc.addIceCandidate(c).catch(() => {})
      }
      const answer = await this.directPc.createAnswer()
      await this.directPc.setLocalDescription(answer)
      this._sendSignal({ type: 'answer', sdp: answer }, localPort)
      return
    }

    if (signal.type === 'answer' && this.directPc) {
      await this.directPc.setRemoteDescription(signal.sdp)
      while (this._pendingRemoteCandidates.length > 0) {
        const c = this._pendingRemoteCandidates.shift()
        await this.directPc.addIceCandidate(c).catch(() => {})
      }
      return
    }

    if (signal.type === 'candidate') {
      if (this.directPc && this.directPc.remoteDescription) {
        await this.directPc.addIceCandidate(signal.candidate).catch(() => {})
      } else {
        this._pendingRemoteCandidates.push(signal.candidate)
      }
    }
  }

  _bindDirectDataChannel (dc) {
    dc.binaryType = 'arraybuffer'
    dc.onopen = () => {
      if (this.closed) return
      this.directDc = dc
      this.isDirectP2P = true
      this.udx.directP2PConnections++
      this.udx.emit('direct-p2p-open', { host: this.host, port: this.port })
    }
    dc.onmessage = (ev) => {
      const data =
        ev.data instanceof ArrayBuffer
          ? new Uint8Array(ev.data)
          : b4a.from(ev.data)
      this.udx.directP2PPacketsRx++
      this._onMessage(b4a.from(data))
    }
  }

  _sendSignal (obj, sourcePort) {
    const jsonBytes = b4a.from(JSON.stringify(obj), 'utf8')
    const sigBuf = b4a.allocUnsafe(1 + jsonBytes.byteLength)
    sigBuf[0] = WEBRTC_SIGNAL_MAGIC
    b4a.copy(jsonBytes, sigBuf, 1)
    this.udx._sendViaBootstrapEnvelope(
      sourcePort || this.lastSourcePort,
      this.host,
      this.port,
      sigBuf
    )
  }

  _onOpen () {
    if (this.closed || this.open) return
    this.open = true
    this.udx._openNativeLinks.add(this)
    while (this.queue.length > 0) {
      const pkt = this.queue.shift()
      this._sendRaw(pkt)
    }
  }

  _sendRaw (pkt) {
    if (this.isDirectP2P && this.directDc && this.directDc.readyState === 'open') {
      this.udx.directP2PPacketsTx++
      this.directDc.send(pkt)
      return
    }
    if (this.dc && this.open) {
      this.dc.send(pkt)
    } else if (this._nodeLink && this.open) {
      this._nodeLink.send(pkt)
    }
  }

  _onMessage (buf) {
    if (this.closed || buf.byteLength === 0) return

    if (buf[0] === PEER_ENVELOPE_MAGIC && buf.byteLength >= 10) {
      this.udx._handlePeerEnvelope(buf)
      return
    }

    if (buf[0] === VPORT_MAGIC && buf.byteLength >= 4) {
      const vport = (buf[1] << 8) | buf[2]
      const inner = b4a.from(buf.subarray(3))
      if (isUdxPacket(inner)) {
        this.udx._routeUdxPacket(
          inner,
          this.host,
          this.port,
          this.isDirectP2P ? this.lastSourcePort : vport
        )
        return
      }
      const sock =
        this.udx._socketsByPort.get(this.isDirectP2P ? this.lastSourcePort : vport) ||
        this.udx._socketsByPort.get(vport)
      if (sock && !sock._closed) {
        sock.emit('message', inner, {
          host: this.host,
          port: this.isDirectP2P ? vport : this.port,
          family: 4
        })
      }
      return
    }

    if (isUdxPacket(buf)) {
      this.udx._routeUdxPacket(b4a.from(buf), this.host, this.port, this.lastSourcePort)
      return
    }

    const preferred = this.lastSourcePort && this.udx._socketsByPort.get(this.lastSourcePort)
    if (preferred && !preferred._closed) {
      preferred.emit('message', b4a.from(buf), {
        host: this.host,
        port: this.port,
        family: 4
      })
      return
    }

    for (const sock of this.udx._socketsByPort.values()) {
      if (!sock._closed) {
        sock.emit('message', b4a.from(buf), {
          host: this.host,
          port: this.port,
          family: 4
        })
        break
      }
    }
  }

  send (buf, sourcePort = 0) {
    if (this.closed) return
    if (sourcePort > 0) this.lastSourcePort = sourcePort
    let out = b4a.from(buf)
    if (sourcePort > 0) {
      const wrapped = b4a.allocUnsafe(3 + out.byteLength)
      wrapped[0] = VPORT_MAGIC
      wrapped[1] = (sourcePort >>> 8) & 0xff
      wrapped[2] = sourcePort & 0xff
      b4a.copy(out, wrapped, 3)
      out = wrapped
    }

    if (this.isDirectP2P && this.directDc && this.directDc.readyState === 'open') {
      this._sendRaw(out)
      return
    }

    if (this.open) {
      this._sendRaw(out)
      return
    }

    if (this.udx._openNativeLinks.size > 0) {
      if (!this._directNegotiationStarted && this.udx.RTCPeerConnection) {
        this._startDirectP2POffer(sourcePort || this.lastSourcePort).catch(() => {})
      }
      this.udx._sendViaBootstrapEnvelope(
        sourcePort || this.lastSourcePort,
        this.host,
        this.port,
        b4a.from(buf)
      )
    }

    this.queue.push(out)
  }

  async close () {
    if (this.closed) return
    this.closed = true
    this.udx._openNativeLinks.delete(this)
    if (this.directPc) {
      try {
        this.directPc.close()
      } catch {}
    }
    if (this.pc) {
      try {
        this.pc.close()
      } catch {}
    }
    if (this._nodeLink) {
      await this._nodeLink.close()
    }
  }
}

class BrowserUDXSocket extends EventEmitter {
  constructor (udx) {
    super()
    this.udx = udx
    this.streams = new Set()
    this.userData = null

    this._host = null
    this._family = 4
    this._port = 0
    this._closing = null
    this._closed = false
  }

  get bound () {
    return this._port !== 0
  }

  get closing () {
    return this._closing !== null
  }

  get idle () {
    return this.streams.size === 0
  }

  get busy () {
    return this.streams.size > 0
  }

  address () {
    if (!this.bound) return null
    return { host: this._host, family: this._family, port: this._port }
  }

  bind (port = 0, host = '0.0.0.0') {
    if (this.bound) throw new Error('Already bound')
    if (this.closing) throw new Error('Socket is closed')

    const assigned = this.udx._allocPort()
    this._port = assigned
    this._host = host || '0.0.0.0'
    this._family = 4
    this.udx._socketsByPort.set(this._port, this)
    this.emit('listening')
  }

  setTTL () {}
  getRecvBufferSize () { return 65536 }
  setRecvBufferSize () {}
  getSendBufferSize () { return 65536 }
  setSendBufferSize () {}

  _addStream (stream) {
    if (this.streams.has(stream)) return false
    this.streams.add(stream)
    if (this.streams.size === 1) this.emit('busy')
    return true
  }

  _removeStream (stream) {
    if (!this.streams.has(stream)) return false
    this.streams.delete(stream)
    const closed = this._closeMaybe()
    if (this.idle && !closed) this.emit('idle')
    return true
  }

  trySend (buffer, port, host) {
    if (this.closing) return
    if (!this.bound) this.bind(0)
    const targetHost = !host || host === '0.0.0.0' ? '127.0.0.1' : host
    this.udx._sendDatagram(this._port, targetHost, port, buffer)
  }

  async send (buffer, port, host) {
    if (this.closing) return false
    this.trySend(buffer, port, host)
    return true
  }

  async close () {
    if (this._closing) return this._closing
    this._closing = new Promise((resolve) => this.once('close', resolve))
    this._closeMaybe()
    return this._closing
  }

  _closeMaybe () {
    if (this._closed || this._closing === null) return this._closed
    if (this.idle) {
      this._closed = true
      if (this._port) this.udx._socketsByPort.delete(this._port)
      this.emit('close')
    }
    return this._closed
  }
}

class BrowserUDXStream extends streamx.Duplex {
  constructor (udx, id, opts = {}) {
    super({ eagerOpen: true })
    this.udx = udx
    this.id = id >>> 0
    this.framed = !!opts.framed
    this.socket = null

    this.remoteId = 0
    this.remoteHost = null
    this.remotePort = 0
    this.remoteFamily = 4
    this.userData = null

    this._firewall = opts.firewall || null
    this._seq = (opts.seq || 0) >>> 0
    this._ack = (opts.ack || 0) >>> 0
    this._remoteAcked = this._seq
    this._remoteEnded = false
    this._localEnded = false
    this._closed = false

    this._inflight = new Map()
    this._ooo = new Map()
    this._pendingWrites = []
    this._retransmitTimer = null
    this._packetsRx = 0
    this._packetsTx = 0

    this.udx._streamsById.set(this.id, this)
  }

  get connected () {
    return this.socket !== null
  }

  get packetsReceived () { return this._packetsRx }
  get packetsTransmitted () { return this._packetsTx }
  get mtu () { return 1200 }
  get rtt () { return 10 }
  get cwnd () { return 64 }
  get inflight () { return this._inflight.size * MAX_PAYLOAD }

  setInteractive () {}
  setKeepalive () {}

  connect (socket, remoteId, port, host, opts = {}) {
    if (this._closed) return
    if (this.connected) throw new Error('Already connected')

    if (!socket.bound) socket.bind(0)

    const targetHost = !host || host === '0.0.0.0' ? '127.0.0.1' : host
    if (opts.ack !== undefined) this._ack = opts.ack >>> 0

    this.socket = socket
    this.remoteId = remoteId >>> 0
    this.remotePort = port
    this.remoteHost = targetHost
    this.remoteFamily = 4

    this.socket._addStream(this)
    this.emit('connect')

    this._retransmitTimer = setInterval(() => this._retransmitUnacked(), 120)
    if (this._retransmitTimer.unref) this._retransmitTimer.unref()

    while (this._pendingWrites.length > 0) {
      const chunk = this._pendingWrites.shift()
      this._sendDataChunk(chunk)
    }
  }

  async changeRemote (socket, remoteId, port, host) {
    if (!this.connected) throw new Error('Not yet connected')
    const prevSocket = this.socket
    const targetHost = !host || host === '0.0.0.0' ? '127.0.0.1' : host

    this.socket = socket
    this.remoteId = remoteId >>> 0
    this.remotePort = port
    this.remoteHost = targetHost
    socket._addStream(this)
    if (prevSocket && prevSocket !== socket) prevSocket._removeStream(this)
    this.emit('remote-changed')
  }

  _write (data, cb) {
    if (this._closed) return cb(null)
    const buf = b4a.isBuffer(data) ? data : b4a.from(data)

    if (!this.connected) {
      this._pendingWrites.push(buf)
      return cb(null)
    }

    this._sendDataChunk(buf)
    cb(null)
  }

  _final (cb) {
    this._localEnded = true
    if (this.connected && !this._closed) {
      const seq = this._seq++
      const pkt = buildPacket({
        localId: this.remoteId,
        type: TYPE.END,
        rwnd: DEFAULT_RWND,
        seq,
        ack: this._ack
      })
      this._inflight.set(seq, { seq, type: TYPE.END, payload: null })
      this._transmitRaw(pkt)
    }
    cb(null)
  }

  _sendDataChunk (buf) {
    let offset = 0
    while (offset < buf.byteLength || buf.byteLength === 0) {
      const slice = buf.subarray(offset, Math.min(offset + MAX_PAYLOAD, buf.byteLength))
      offset += slice.byteLength
      const seq = this._seq++
      const pkt = buildPacket({
        localId: this.remoteId,
        type: TYPE.DATA,
        rwnd: DEFAULT_RWND,
        seq,
        ack: this._ack,
        payload: slice
      })
      this._inflight.set(seq, { seq, type: TYPE.DATA, payload: b4a.from(slice) })
      this._transmitRaw(pkt)
      if (buf.byteLength === 0) break
    }
  }

  _retransmitUnacked () {
    if (this._closed || !this.connected || this._inflight.size === 0) return
    for (const item of this._inflight.values()) {
      const pkt = buildPacket({
        localId: this.remoteId,
        type: item.type,
        rwnd: DEFAULT_RWND,
        seq: item.seq,
        ack: this._ack,
        payload: item.payload
      })
      this._transmitRaw(pkt)
    }
  }

  _transmitRaw (pkt) {
    if (!this.socket || this._closed) return
    this._packetsTx++
    this.udx.udxPacketsTx++
    this.udx._sendDatagram(this.socket._port, this.remoteHost, this.remotePort, pkt)
  }

  _sendAck () {
    if (!this.connected || this._closed) return
    const pkt = buildPacket({
      localId: this.remoteId,
      type: 0,
      rwnd: DEFAULT_RWND,
      seq: this._seq,
      ack: this._ack
    })
    this._transmitRaw(pkt)
  }

  _onPacket (pkt, fromHost, fromPort, vport) {
    if (this._closed) return
    this._packetsRx++
    this.udx.udxPacketsRx++

    if (!this.connected && this._firewall) {
      const sock =
        (vport && this.udx._socketsByPort.get(vport)) ||
        this.udx._socketsByPort.values().next().value
      if (sock) {
        const reject = this._firewall(sock, fromPort, fromHost)
        if (reject) return
      }
    }

    if (pkt.type & TYPE.DESTROY) {
      this.destroy(new Error('Stream destroyed by remote'))
      return
    }

    for (const seq of this._inflight.keys()) {
      if (((pkt.ack - seq) | 0) > 0) {
        this._inflight.delete(seq)
      }
    }
    if (((pkt.ack - this._remoteAcked) | 0) > 0) {
      this._remoteAcked = pkt.ack
    }

    if (pkt.type & TYPE.HEARTBEAT) {
      this._sendAck()
      return
    }

    const hasSeq = (pkt.type & (TYPE.DATA | TYPE.END)) !== 0
    if (hasSeq) {
      const diff = (pkt.seq - this._ack) | 0
      if (diff === 0) {
        this._consumeInOrder(pkt)
        while (this._ooo.has(this._ack)) {
          const next = this._ooo.get(this._ack)
          this._ooo.delete(this._ack)
          this._consumeInOrder(next)
        }
      } else if (diff > 0) {
        this._ooo.set(pkt.seq, pkt)
      }
      this._sendAck()
    }
  }

  _consumeInOrder (pkt) {
    this._ack = (this._ack + 1) >>> 0
    if ((pkt.type & TYPE.DATA) && pkt.payload && pkt.payload.byteLength > 0) {
      this.push(b4a.from(pkt.payload))
    }
    if ((pkt.type & TYPE.END) && !this._remoteEnded) {
      this._remoteEnded = true
      this.push(null)
    }
  }

  _predestroy () {
    this._cleanup()
  }

  _destroy (cb) {
    this._cleanup()
    cb(null)
  }

  _cleanup () {
    if (this._closed) return
    this._closed = true
    if (this._retransmitTimer) {
      clearInterval(this._retransmitTimer)
      this._retransmitTimer = null
    }
    this._inflight.clear()
    this._ooo.clear()
    this.udx._streamsById.delete(this.id)
    if (this.socket) {
      const s = this.socket
      this.socket = null
      s._removeStream(this)
    }
  }
}

class BrowserUDX extends EventEmitter {
  constructor (opts = {}) {
    super()
    this.fingerprint = opts.fingerprint || DEFAULT_CERT.fingerprint
    this.iceUfrag = opts.iceUfrag || DEFAULT_ICE_UFRAG
    this.icePwd = opts.icePwd || DEFAULT_ICE_PWD
    this.iceServers = opts.iceServers || DEFAULT_ICE_SERVERS
    this.RTCPeerConnection =
      opts.RTCPeerConnection ||
      globalThis.RTCPeerConnection ||
      null

    // Assign each browser instance a routable non-bogon virtual IP (11.x.y.z) for serverless cross-network DHT mesh
    this.localIp =
      opts.localIp ||
      `11.${1 + ((Math.random() * 250) | 0)}.${1 + ((Math.random() * 250) | 0)}.${1 + ((Math.random() * 250) | 0)}`

    this._nextPort = 15000 + ((Math.random() * 45000) | 0)
    this._socketsByPort = new Map()
    this._streamsById = new Map()
    this._links = new Map()
    this._openNativeLinks = new Set()
    this._meshChannels = new Map() // remoteVirtualIp -> RTCDataChannel

    this.udxPacketsTx = 0
    this.udxPacketsRx = 0
    this.directP2PConnections = 0
    this.directP2PPacketsTx = 0
    this.directP2PPacketsRx = 0
  }

  static isIPv4 (host) {
    return /^\d{1,3}(\.\d{1,3}){3}$/.test(host)
  }

  static isIPv6 (host) {
    return host.includes(':')
  }

  static isIP (host) {
    if (BrowserUDX.isIPv4(host)) return 4
    if (BrowserUDX.isIPv6(host)) return 6
    return 0
  }

  // Attach a direct WebRTC DataChannel to another browser instance's virtual IP (11.x.y.z)
  attachPeerChannel (remoteIp, dc) {
    if (this._meshChannels.get(remoteIp) === dc) return
    this._meshChannels.set(remoteIp, dc)
    this.directP2PConnections = this._meshChannels.size
    dc.binaryType = 'arraybuffer'
    dc.onmessage = (ev) => {
      const data =
        ev.data instanceof ArrayBuffer
          ? new Uint8Array(ev.data)
          : b4a.from(ev.data)
      this.directP2PPacketsRx++
      this._handlePeerEnvelope(b4a.from(data))
    }
    dc.onclose = () => {
      if (this._meshChannels.get(remoteIp) === dc) {
        this._meshChannels.delete(remoteIp)
        this.directP2PConnections = this._meshChannels.size
      }
    }
    this.emit('direct-p2p-open', { host: remoteIp, port: 49737 })
  }

  _sendDatagram (srcPort, dstHost, dstPort, payload) {
    const buf = b4a.from(payload)

    // 1. In-browser loopback when targeting our own virtual IP (e.g. embedded HyperDHT bootstrapper)
    if (dstHost === this.localIp && this._socketsByPort.has(dstPort)) {
      queueMicrotask(() => {
        if (isUdxPacket(buf)) {
          this._routeUdxPacket(buf, this.localIp, srcPort, dstPort)
        } else {
          const sock = this._socketsByPort.get(dstPort)
          if (sock && !sock._closed) {
            sock.emit('message', buf, {
              host: this.localIp,
              port: srcPort,
              family: 4
            })
          }
        }
      })
      return
    }

    // 2. Direct Browser-to-Browser WebRTC Mesh Channel for remote browser virtual IP (11.x.y.z)
    const meshDc = this._meshChannels.get(dstHost)
    if (meshDc && meshDc.readyState === 'open') {
      const ipParts = this.localIp.split('.').map(Number)
      const env = b4a.allocUnsafe(9 + buf.byteLength)
      env[0] = PEER_ENVELOPE_MAGIC
      env[1] = (srcPort >>> 8) & 0xff
      env[2] = srcPort & 0xff
      env[3] = (ipParts[0] || 11) & 0xff
      env[4] = (ipParts[1] || 1) & 0xff
      env[5] = (ipParts[2] || 1) & 0xff
      env[6] = (ipParts[3] || 1) & 0xff
      env[7] = (dstPort >>> 8) & 0xff
      env[8] = dstPort & 0xff
      b4a.copy(buf, env, 9)
      this.directP2PPacketsTx++
      meshDc.send(env)
      return
    }

    // 3. Native WebBridgeUDX UDP Link (or upgraded BrowserPeerLink)
    const link = this._getOrCreateLink(dstHost, dstPort)
    link.send(buf, srcPort)
  }

  _handlePeerEnvelope (buf) {
    if (buf.byteLength < 10 || buf[0] !== PEER_ENVELOPE_MAGIC) return
    const srcPort = (buf[1] << 8) | buf[2]
    const fromHost = `${buf[3]}.${buf[4]}.${buf[5]}.${buf[6]}`
    const dstPort = (buf[7] << 8) | buf[8]
    const inner = b4a.from(buf.subarray(9))

    if (!this._meshChannels.has(fromHost)) {
      const peerLink = this._getOrCreateLink(fromHost, srcPort)
      if (dstPort > 0) peerLink.lastSourcePort = dstPort
      if (inner[0] === WEBRTC_SIGNAL_MAGIC) {
        try {
          const signal = JSON.parse(b4a.toString(inner.subarray(1)))
          peerLink._handleSignal(signal, dstPort).catch(() => {})
        } catch {}
        return
      }
    }

    if (isUdxPacket(inner)) {
      this._routeUdxPacket(inner, fromHost, srcPort, dstPort)
      return
    }

    const sock = this._socketsByPort.get(dstPort)
    if (sock && !sock._closed) {
      sock.emit('message', inner, {
        host: fromHost,
        port: srcPort,
        family: 4
      })
    }
  }

  _allocPort () {
    while (this._socketsByPort.has(this._nextPort) || this._nextPort >= 65000) {
      this._nextPort = 15000 + ((Math.random() * 45000) | 0)
    }
    return this._nextPort++
  }

  _getOrCreateLink (host, port) {
    const key = `${host}:${port}`
    let link = this._links.get(key)
    if (!link || link.closed) {
      link = new BrowserPeerLink(this, host, port)
      this._links.set(key, link)
    }
    return link
  }

  _sendViaBootstrapEnvelope (srcPort, dstHost, dstPort, payload) {
    const [bootLink] = this._openNativeLinks
    if (!bootLink || bootLink.closed) return false

    const ipParts = (dstHost || '127.0.0.1').split('.').map(Number)
    const env = b4a.allocUnsafe(9 + payload.byteLength)
    env[0] = PEER_ENVELOPE_MAGIC
    env[1] = (srcPort >>> 8) & 0xff
    env[2] = srcPort & 0xff
    env[3] = (ipParts[0] || 127) & 0xff
    env[4] = (ipParts[1] || 0) & 0xff
    env[5] = (ipParts[2] || 0) & 0xff
    env[6] = (ipParts[3] || 1) & 0xff
    env[7] = (dstPort >>> 8) & 0xff
    env[8] = dstPort & 0xff
    b4a.copy(payload, env, 9)

    bootLink._sendRaw(env)
    return true
  }

  _routeUdxPacket (buf, fromHost, fromPort, vport) {
    const pkt = parsePacket(buf)
    if (!pkt) return
    const stream = this._streamsById.get(pkt.localId)
    if (stream) {
      stream._onPacket(pkt, fromHost, fromPort, vport)
    }
  }

  createSocket (opts) {
    return new BrowserUDXSocket(this, opts)
  }

  createStream (id, opts) {
    return new BrowserUDXStream(this, id, opts)
  }

  networkInterfaces () {
    return [{ name: 'web0', host: '0.0.0.0', family: 4, internal: false }]
  }

  watchNetworkInterfaces (onchange) {
    const watcher = new EventEmitter()
    watcher.interfaces = this.networkInterfaces()
    watcher.watch = () => watcher
    watcher.destroy = () => watcher.emit('close')
    if (onchange) watcher.on('change', onchange)
    return watcher
  }

  async destroy () {
    const closing = []
    for (const link of this._links.values()) {
      closing.push(link.close())
    }
    for (const dc of this._meshChannels.values()) {
      try { dc.close() } catch {}
    }
    this._links.clear()
    this._meshChannels.clear()
    this._openNativeLinks.clear()
    await Promise.allSettled(closing)
  }
}

module.exports = BrowserUDX
