'use strict'

const dgram = require('dgram')
const b4a = require('b4a')
const UDX = require('udx-native')
const {
  VPORT_MAGIC,
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

    // Ephemeral loopback UDP socket so C libudx eats and spits real 0xff 0x01 UDX packets in native code
    this.loopback = dgram.createSocket('udp4')
    this.loopback.on('message', (msg) => {
      if (this.closed) return
      // C libudx just squirted a raw 0xff 0x01 UDX packet to our loopback port — ride it down the DataChannel
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

    // Zero-dependency DTLS 1.2 Server + SCTP DataChannel bound straight to this UDXSocket
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

  _onDataChannelDatagram (buf) {
    if (buf.byteLength === 0) return

    // Virtual source-port envelope [0xfe, portHi, portLo, ...payload] for Nat.autoSample / SocketPool multiplexing
    if (buf[0] === VPORT_MAGIC && buf.byteLength >= 4) {
      const vport = (buf[1] << 8) | buf[2]
      const inner = b4a.from(buf.subarray(3))
      const vkey = `${this.peerHost}:${vport}`
      this.lastVport = vport
      this.socket._vportSessions.set(vkey, { session: this, vport })
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

    // Real 20-byte UDX v1 packet (0xff 0x01): feed straight into C libudx via loopback UDP
    if (isUdxPacket(buf)) {
      this._injectUdxPacket(buf)
      return
    }

    // Standard dht-rpc (0x03 / 0x13) or 1-byte holepunch probe (0x00)
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
    if (vport > 0 && !isUdxPacket(out)) {
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
    try {
      this.loopback.close()
    } catch {}
    this.sctp.close()
    this.dtls.close()
  }
}

// Drop-in UDX replacement for native Holepunch apps that demuxes STUN + DTLS + UDX on every UDXSocket
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
    // Wrap pre-connect firewall callback so loopback UDX injection reports the browser's real host:port
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

    socket._ensureSession = (host, port) => {
      const key = `${host}:${port}`
      let session = socket._peerSessions.get(key)
      if (!session) {
        session = new NativePeerSession(this, socket, host, port)
        socket._peerSessions.set(key, session)
      }
      return session
    }

    // Intercept non-0xff UDP datagrams at the mouth of UDXSocket before dht-rpc or Holepuncher sees them
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
