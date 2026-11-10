'use strict'

const dgram = require('dgram')
const b4a = require('b4a')
const UDX = require('udx-native')
const {
  VPORT_MAGIC,
  PEER_ENVELOPE_MAGIC,
  isStunPacket,
  isDtlsPacket,
  isUdxPacket
} = require('./wire')
const {
  DEFAULT_ICE_UFRAG,
  DEFAULT_ICE_PWD,
  DEFAULT_CERT
} = require('./cert')
const {
  BINDING_REQUEST,
  parseStun,
  buildBindingResponse
} = require('./stun')
const { DtlsEndpoint } = require('./dtls')
const { SctpEndpoint } = require('./sctp')

const GLOBAL_VPORT_SESSIONS = new Map()
const GLOBAL_WEBBRIDGE_PORTS = new Set()

// Per-browser-peer session living on a native UDXSocket's single UDP port
class NativePeerSession {
  constructor (bridge, socket, peerHost, peerPort) {
    this.bridge = bridge
    this.socket = socket
    this.peerHost = peerHost
    this.peerPort = peerPort
    this.lastVport = peerPort
    this.key = `${peerHost}:${peerPort}`

    this.dcOpen = false
    this.pendingDatagrams = []
    this.pendingLoopback = []
    this.loopbackPort = 0
    this.closed = false

    // Per-vport real OS UDP sockets bound to `vport` so 100% stock native peers can exchange raw UDP with browser peers
    this.udpProxies = new Map()

    this.loopback = dgram.createSocket('udp4')
    this.loopback.on('message', (msg) => {
      if (this.closed) return
      this.sendDatagram(Buffer.from(msg))
    })
    this.loopback.bind(0, '127.0.0.1', () => {
      if (this.closed) return
      this.loopbackPort = this.loopback.address().port
      this.socket._loopbackToPeer.set(this.loopbackPort, this)
      const targetPort = this.socket.address().port
      while (this.pendingLoopback.length > 0) {
        const pkt = this.pendingLoopback.shift()
        this.loopback.send(pkt, targetPort, '127.0.0.1')
      }
    })
    if (this.loopback.unref) this.loopback.unref()

    this.dtls = new DtlsEndpoint({
      role: 'server',
      cert: bridge.cert,
      send: (dtlsPacket) => {
        if (this.closed || socket.closing) return
        socket._rawTrySend(dtlsPacket, this.peerPort, this.peerHost)
      }
    })

    this.sctp = new SctpEndpoint({
      role: 'server',
      port: 5000,
      send: (sctpPacket) => {
        this.dtls.send(sctpPacket)
      }
    })

    this.dtls.on('data', (sctpPacket) => {
      if (!this.closed) this.sctp.feedPacket(sctpPacket)
    })

    this.sctp.on('open', () => {
      if (this.closed || this.dcOpen) return
      this.dcOpen = true
      while (this.pendingDatagrams.length > 0) {
        const next = this.pendingDatagrams.shift()
        this.sctp.sendData(next, 0)
      }
    })

    this.sctp.on('message', (buf) => {
      if (!this.closed) this._onDataChannelDatagram(buf)
    })
  }

  _registerVport (vport) {
    const vkey = `${this.peerHost}:${vport}`
    const entry = { session: this, vport }
    this.lastVport = vport
    this.socket._vportSessions.set(vkey, entry)
    if (!GLOBAL_VPORT_SESSIONS.has(vkey)) {
      GLOBAL_VPORT_SESSIONS.set(vkey, entry)
      this._getOrCreateUdpProxy(vport, () => {})
    }
  }

  // Bind a real OS UDP socket on `vport` so stock (unmodified) native peers can exchange raw UDP with this browser
  _getOrCreateUdpProxy (vport, onReady) {
    let proxy = this.udpProxies.get(vport)
    if (!proxy) {
      const sock = dgram.createSocket('udp4')
      if (sock.unref) sock.unref()
      proxy = { sock, vport, ready: false, pending: [] }
      this.udpProxies.set(vport, proxy)

      sock.on('message', (msg, rinfo) => {
        if (this.closed) return
        const ipParts = (rinfo.address || '127.0.0.1').split('.').map(Number)
        const env = Buffer.allocUnsafe(9 + msg.byteLength)
        env[0] = PEER_ENVELOPE_MAGIC
        env[1] = (rinfo.port >>> 8) & 0xff
        env[2] = rinfo.port & 0xff
        env[3] = (ipParts[0] || 127) & 0xff
        env[4] = (ipParts[1] || 0) & 0xff
        env[5] = (ipParts[2] || 0) & 0xff
        env[6] = (ipParts[3] || 1) & 0xff
        env[7] = (vport >>> 8) & 0xff
        env[8] = vport & 0xff
        msg.copy(env, 9)
        this.sendDatagram(env, 0)
      })

      const bindHost = this.peerHost === '127.0.0.1' ? '127.0.0.1' : '0.0.0.0'
      const finishBind = () => {
        if (this.closed) return
        proxy.ready = true
        while (proxy.pending.length > 0) {
          const fn = proxy.pending.shift()
          fn(proxy)
        }
      }

      sock.once('error', () => {
        try {
          sock.bind(0, bindHost, finishBind)
        } catch {}
      })
      sock.bind(vport, bindHost, finishBind)
    }

    if (proxy.ready) {
      onReady(proxy)
    } else {
      proxy.pending.push(onReady)
    }
  }

  _onDataChannelDatagram (buf) {
    if (buf.byteLength === 0) return

    // Peer envelope [0xfd, srcPortHi, srcPortLo, dstIp0..3, dstPortHi, dstPortLo, ...payload]
    if (buf[0] === PEER_ENVELOPE_MAGIC && buf.byteLength >= 10) {
      const srcPort = (buf[1] << 8) | buf[2]
      const dstHost = `${buf[3]}.${buf[4]}.${buf[5]}.${buf[6]}`
      const dstPort = (buf[7] << 8) | buf[8]
      const inner = buf.subarray(9)
      this._registerVport(srcPort)

      const dstKey = `${dstHost}:${dstPort}`
      const dst =
        this.socket._vportSessions.get(dstKey) ||
        GLOBAL_VPORT_SESSIONS.get(dstKey)

      if (dst && !dst.session.closed) {
        const fwd = Buffer.from(buf)
        const srcParts = this.peerHost.split('.').map(Number)
        if (srcParts.length === 4) {
          fwd[3] = srcParts[0] & 0xff
          fwd[4] = srcParts[1] & 0xff
          fwd[5] = srcParts[2] & 0xff
          fwd[6] = srcParts[3] & 0xff
        }
        dst.session.sendDatagram(fwd, 0)
        return
      }

      // Destination is not a browser vport and not a WebBridgeUDX socket -> transmit raw UDP to stock native peer!
      if (inner[0] === 0xfc) return
      if (GLOBAL_WEBBRIDGE_PORTS.has(dstKey)) return
      this._getOrCreateUdpProxy(srcPort, (proxy) => {
        if (!this.closed) {
          proxy.sock.send(inner, dstPort, dstHost)
        }
      })
      return
    }

    // Virtual source-port envelope [0xfe, portHi, portLo, ...payload]
    if (buf[0] === VPORT_MAGIC && buf.byteLength >= 4) {
      const vport = (buf[1] << 8) | buf[2]
      const inner = b4a.from(buf.subarray(3))
      this._registerVport(vport)
      if (isUdxPacket(inner)) {
        this._injectUdxPacket(inner)
        return
      }
      this.socket.emit('message', inner, {
        host: this.peerHost,
        port: vport,
        family: 4
      })
      return
    }

    if (isUdxPacket(buf)) {
      this._injectUdxPacket(buf)
      return
    }

    this.socket.emit('message', b4a.from(buf), {
      host: this.peerHost,
      port: this.peerPort,
      family: 4
    })
  }

  _injectUdxPacket (buf) {
    if (this.loopbackPort > 0) {
      const targetPort = this.socket.address().port
      this.loopback.send(buf, targetPort, '127.0.0.1')
    } else {
      this.pendingLoopback.push(Buffer.from(buf))
    }
  }

  sendDatagram (buf, vport = 0) {
    if (this.closed) return
    let out = Buffer.from(buf)
    if (vport > 0 && out[0] !== PEER_ENVELOPE_MAGIC && !isUdxPacket(out)) {
      const wrapped = Buffer.allocUnsafe(3 + out.byteLength)
      wrapped[0] = VPORT_MAGIC
      wrapped[1] = (vport >>> 8) & 0xff
      wrapped[2] = vport & 0xff
      out.copy(wrapped, 3)
      out = wrapped
    }
    if (this.dcOpen && this.sctp.open) {
      this.sctp.sendData(out, 0)
    } else {
      this.pendingDatagrams.push(out)
    }
  }

  feedDtls (buf) {
    if (this.closed) return
    this.dtls.feedPacket(buf)
  }

  destroy () {
    if (this.closed) return
    this.closed = true
    if (this.loopbackPort) {
      this.socket._loopbackToPeer.delete(this.loopbackPort)
    }
    for (const [k, v] of GLOBAL_VPORT_SESSIONS.entries()) {
      if (v.session === this) GLOBAL_VPORT_SESSIONS.delete(k)
    }
    for (const proxy of this.udpProxies.values()) {
      try {
        proxy.sock.close()
      } catch {}
    }
    this.udpProxies.clear()
    try {
      this.loopback.close()
    } catch {}
    this.sctp.close()
    this.dtls.close()
  }
}

class WebBridgeUDX extends UDX {
  constructor (opts = {}) {
    super()
    this.cert = opts.cert || DEFAULT_CERT
    this.iceUfrag = opts.iceUfrag || DEFAULT_ICE_UFRAG
    this.icePwd = opts.icePwd || DEFAULT_ICE_PWD
  }

  get fingerprint () {
    return this.cert.fingerprint
  }

  createSocket (opts) {
    const socket = super.createSocket(opts)
    this._instrumentSocket(socket)
    return socket
  }

  createStream (id, opts = {}) {
    if (typeof opts.firewall === 'function') {
      const origFirewall = opts.firewall
      opts = {
        ...opts,
        firewall: (sock, port, host) => {
          if (host === '127.0.0.1' && sock && sock._loopbackToPeer) {
            const session = sock._loopbackToPeer.get(port)
            if (session) {
              return origFirewall(
                sock,
                session.lastVport || session.peerPort,
                session.peerHost
              )
            }
          }
          return origFirewall(sock, port, host)
        }
      }
    }

    const stream = super.createStream(id, opts)
    const origConnect = stream.connect.bind(stream)
    const origChangeRemote = stream.changeRemote.bind(stream)

    stream.connect = (socket, remoteId, port, host, connectOpts) => {
      const targetHost = host || '127.0.0.1'
      const key = `${targetHost}:${port}`
      const session =
        socket && socket._peerSessions
          ? socket._peerSessions.get(key) ||
            (socket._vportSessions.get(key) &&
              socket._vportSessions.get(key).session)
          : null

      if (session && session.loopbackPort > 0) {
        const res = origConnect(
          socket,
          remoteId,
          session.loopbackPort,
          '127.0.0.1',
          connectOpts
        )
        stream.remoteHost = targetHost
        stream.remotePort = port
        return res
      }

      return origConnect(socket, remoteId, port, host, connectOpts)
    }

    stream.changeRemote = (socket, remoteId, port, host) => {
      const targetHost = host || '127.0.0.1'
      const key = `${targetHost}:${port}`
      const session =
        socket && socket._peerSessions
          ? socket._peerSessions.get(key) ||
            (socket._vportSessions.get(key) &&
              socket._vportSessions.get(key).session)
          : null

      if (session && session.loopbackPort > 0) {
        const p = origChangeRemote(
          socket,
          remoteId,
          session.loopbackPort,
          '127.0.0.1'
        )
        stream.remoteHost = targetHost
        stream.remotePort = port
        return p
      }

      return origChangeRemote(socket, remoteId, port, host)
    }

    return stream
  }

  _instrumentSocket (socket) {
    socket._peerSessions = new Map()
    socket._vportSessions = new Map()
    socket._loopbackToPeer = new Map()

    const rawSend = socket.send.bind(socket)
    const rawTrySend = socket.trySend.bind(socket)

    socket._rawSend = rawSend
    socket._rawTrySend = rawTrySend

    socket.on('listening', () => {
      const addr = socket.address()
      if (addr) {
        const h = addr.host === '0.0.0.0' || addr.host === '::' ? '127.0.0.1' : addr.host
        GLOBAL_WEBBRIDGE_PORTS.add(`${h}:${addr.port}`)
      }
    })

    socket._ensureSession = (host, port) => {
      const key = `${host}:${port}`
      let session = socket._peerSessions.get(key)
      if (!session) {
        session = new NativePeerSession(this, socket, host, port)
        socket._peerSessions.set(key, session)
      }
      return session
    }

    socket._onmessage = (len, port, host, family) => {
      const slice = this._consumeMessage(len)
      const buf = Buffer.from(slice)

      if (isStunPacket(buf)) {
        const parsed = parseStun(buf)
        if (parsed && parsed.type === BINDING_REQUEST) {
          socket._ensureSession(host, port)
          const resp = buildBindingResponse({
            transactionId: parsed.transactionId,
            host,
            port,
            icePwd: parsed.username ? this.icePwd : null
          })
          rawTrySend(resp, port, host, 0)
        }
        return this._buffer
      }

      if (isDtlsPacket(buf)) {
        const session = socket._ensureSession(host, port)
        session.feedDtls(buf)
        return this._buffer
      }

      socket.emit('message', b4a.from(buf), { host, family, port })
      return this._buffer
    }

    socket.trySend = (buffer, port, host, ttl) => {
      const targetHost = host || '127.0.0.1'
      const key = `${targetHost}:${port}`

      const vroute = socket._vportSessions.get(key)
      if (vroute && !vroute.session.closed) {
        vroute.session.sendDatagram(buffer, vroute.vport)
        return
      }

      const direct = socket._peerSessions.get(key)
      if (direct && !direct.closed) {
        direct.sendDatagram(buffer, 0)
        if (!direct.dcOpen) {
          rawTrySend(buffer, port, targetHost, ttl)
        }
        return
      }

      return rawTrySend(buffer, port, targetHost, ttl)
    }

    socket.send = async (buffer, port, host, ttl) => {
      const targetHost = host || '127.0.0.1'
      const key = `${targetHost}:${port}`

      const vroute = socket._vportSessions.get(key)
      if (vroute && !vroute.session.closed) {
        vroute.session.sendDatagram(buffer, vroute.vport)
        return true
      }

      const direct = socket._peerSessions.get(key)
      if (direct && !direct.closed) {
        direct.sendDatagram(buffer, 0)
        if (!direct.dcOpen) {
          await rawSend(buffer, port, targetHost, ttl)
        }
        return true
      }

      return rawSend(buffer, port, targetHost, ttl)
    }

    socket.on('close', () => {
      const addr = socket.address()
      if (addr) {
        const h = addr.host === '0.0.0.0' || addr.host === '::' ? '127.0.0.1' : addr.host
        GLOBAL_WEBBRIDGE_PORTS.delete(`${h}:${addr.port}`)
      }
      for (const session of socket._peerSessions.values()) {
        session.destroy()
      }
      socket._peerSessions.clear()
      socket._vportSessions.clear()
      socket._loopbackToPeer.clear()
    })
  }
}

module.exports = WebBridgeUDX
