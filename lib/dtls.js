'use strict'

const crypto = require('crypto')
const { EventEmitter } = require('events')
const { DEFAULT_CERT, pemToDer } = require('./cert')

// DTLS 1.2 constants (RFC 6347 + RFC 5289 TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = 0xc02b)
const CONTENT_CHANGE_CIPHER_SPEC = 20
const CONTENT_ALERT = 21
const CONTENT_HANDSHAKE = 22
const CONTENT_APPLICATION_DATA = 23

const HANDSHAKE_CLIENT_HELLO = 1
const HANDSHAKE_SERVER_HELLO = 2
const HANDSHAKE_HELLO_VERIFY_REQUEST = 3
const HANDSHAKE_CERTIFICATE = 11
const HANDSHAKE_SERVER_KEY_EXCHANGE = 12
const HANDSHAKE_CERTIFICATE_REQUEST = 13
const HANDSHAKE_SERVER_HELLO_DONE = 14
const HANDSHAKE_CERTIFICATE_VERIFY = 15
const HANDSHAKE_CLIENT_KEY_EXCHANGE = 16
const HANDSHAKE_FINISHED = 20

const CIPHER_ECDHE_ECDSA_AES128_GCM_SHA256 = 0xc02b
const NAMED_CURVE_P256 = 0x0017

// TLS 1.2 P_SHA256 Pseudo-Random Function (RFC 5246 S5)
function prfSha256 (secret, label, seed, length) {
  const fullSeed = Buffer.concat([Buffer.from(label, 'ascii'), seed])
  let a = fullSeed
  const chunks = []
  let total = 0

  while (total < length) {
    a = crypto.createHmac('sha256', secret).update(a).digest()
    const out = crypto
      .createHmac('sha256', secret)
      .update(Buffer.concat([a, fullSeed]))
      .digest()
    chunks.push(out)
    total += out.length
  }

  return Buffer.concat(chunks, total).subarray(0, length)
}

function writeUInt24BE (buf, val, off) {
  buf[off] = (val >>> 16) & 0xff
  buf[off + 1] = (val >>> 8) & 0xff
  buf[off + 2] = val & 0xff
}

function readUInt24BE (buf, off) {
  return (buf[off] << 16) | (buf[off + 1] << 8) | buf[off + 2]
}

function writeUInt48BE (buf, val, off) {
  const hi = Math.floor(val / 0x100000000)
  const lo = val >>> 0
  buf.writeUInt16BE(hi & 0xffff, off)
  buf.writeUInt32BE(lo, off + 2)
}

// Wrap a DTLS handshake body in its 12-byte unfragmented DTLS handshake header
function wrapHandshake (msgType, msgSeq, body) {
  const out = Buffer.allocUnsafe(12 + body.length)
  out[0] = msgType
  writeUInt24BE(out, body.length, 1)
  out.writeUInt16BE(msgSeq, 4)
  writeUInt24BE(out, 0, 6) // fragment_offset = 0
  writeUInt24BE(out, body.length, 9) // fragment_length = length
  body.copy(out, 12)
  return out
}

// Wrap a payload in a 13-byte DTLS 1.2 record header (0xfefd)
function wrapRecord (contentType, epoch, seq, payload) {
  const out = Buffer.allocUnsafe(13 + payload.length)
  out[0] = contentType
  out[1] = 0xfe
  out[2] = 0xfd
  out.writeUInt16BE(epoch, 3)
  writeUInt48BE(out, seq, 5)
  out.writeUInt16BE(payload.length, 11)
  payload.copy(out, 13)
  return out
}

// Zero-dependency DTLS 1.2 endpoint (supports both passive Server and active Client roles)
class DtlsEndpoint extends EventEmitter {
  constructor ({ role = 'server', cert = DEFAULT_CERT, send }) {
    super()
    this.role = role
    this.cert = {
      ...cert,
      certDer: cert.certDer || pemToDer(cert.certPem)
    }
    this._sendRaw = send
    this.connected = false
    this.closed = false

    this.epoch = 0
    this.recordSeq = [0, 0]
    this.handshakeSeqOut = 0

    this.clientRandom = null
    this.serverRandom = null
    this.useExtendedMasterSecret = false
    this.selectedSrtpProfile = 0x0001
    this.cookie = crypto.randomBytes(16)

    this.ecdh = crypto.createECDH('prime256v1')
    this.ecdh.generateKeys()

    this.transcript = []
    this.handshakeFragments = new Map()

    this.masterSecret = null
    this.localWriteKey = null
    this.remoteWriteKey = null
    this.localWriteIV = null
    this.remoteWriteIV = null
    this.remoteEpoch = 0
  }

  // Start active DTLS 1.2 Client handshake (used by Node-side BrowserUDX client)
  startClient (cookie = Buffer.alloc(0)) {
    if (this.closed) return
    if (!this.clientRandom) this.clientRandom = crypto.randomBytes(32)
    this.transcript = []

    const body = this._buildClientHelloBody(cookie)
    const hs = wrapHandshake(HANDSHAKE_CLIENT_HELLO, this.handshakeSeqOut++, body)
    if (cookie.length > 0) {
      this.transcript.push(hs)
    }
    this._sendRecord(CONTENT_HANDSHAKE, 0, hs)
  }

  _buildClientHelloBody (cookie) {
    // Extensions: extended_master_secret (0x0017), renegotiation_info (0xff01), supported_groups (0x000a), ec_point_formats (0x000b), signature_algorithms (0x000d), use_srtp (0x000e)
    const exts = Buffer.from([
      0x00, 0x17, 0x00, 0x00, // extended_master_secret
      0xff, 0x01, 0x00, 0x01, 0x00, // renegotiation_info
      0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x17, // supported_groups: secp256r1
      0x00, 0x0b, 0x00, 0x02, 0x01, 0x00, // ec_point_formats: uncompressed
      0x00, 0x0d, 0x00, 0x04, 0x00, 0x02, 0x04, 0x03, // signature_algorithms: ecdsa_secp256r1_sha256
      0x00, 0x0e, 0x00, 0x05, 0x00, 0x02, 0x00, 0x01, 0x00 // use_srtp: SRTP_AES128_CM_HMAC_SHA1_80
    ])

    const buf = Buffer.allocUnsafe(2 + 32 + 1 + 1 + cookie.length + 4 + 2 + 2 + exts.length)
    let off = 0
    buf[off++] = 0xfe
    buf[off++] = 0xfd
    this.clientRandom.copy(buf, off)
    off += 32
    buf[off++] = 0 // session_id len
    buf[off++] = cookie.length
    if (cookie.length > 0) {
      cookie.copy(buf, off)
      off += cookie.length
    }
    buf.writeUInt16BE(2, off) // cipher_suites len
    buf.writeUInt16BE(CIPHER_ECDHE_ECDSA_AES128_GCM_SHA256, off + 2)
    off += 4
    buf[off++] = 1 // compression_methods len
    buf[off++] = 0 // null compression
    buf.writeUInt16BE(exts.length, off)
    off += 2
    exts.copy(buf, off)
    return buf
  }

  // Feed an incoming UDP datagram carrying one or more DTLS records
  feedPacket (buf) {
    if (this.closed) return
    let off = 0
    while (off + 13 <= buf.byteLength) {
      const contentType = buf[off]
      const versionHi = buf[off + 1]
      const versionLo = buf[off + 2]
      const epoch = buf.readUInt16BE(off + 3)
      const seqBytes = buf.subarray(off + 3, off + 11) // 8-byte epoch + sequence_number
      const recLen = buf.readUInt16BE(off + 11)
      if (off + 13 + recLen > buf.byteLength) break

      let fragment = buf.subarray(off + 13, off + 13 + recLen)
      off += 13 + recLen

      if (epoch > 0) {
        if (!this.remoteWriteKey) continue
        const decrypted = this._decryptRecord(contentType, versionHi, versionLo, seqBytes, fragment)
        if (!decrypted) continue
        fragment = decrypted
      }

      if (contentType === CONTENT_CHANGE_CIPHER_SPEC) {
        this.remoteEpoch = 1
      } else if (contentType === CONTENT_HANDSHAKE) {
        this._handleHandshakeRecord(fragment)
      } else if (contentType === CONTENT_APPLICATION_DATA && this.connected) {
        this.emit('data', Buffer.from(fragment))
      }
    }
  }

  _handleHandshakeRecord (buf) {
    let off = 0
    while (off + 12 <= buf.byteLength) {
      const msgType = buf[off]
      const msgLen = readUInt24BE(buf, off + 1)
      const msgSeq = buf.readUInt16BE(off + 4)
      const fragOff = readUInt24BE(buf, off + 6)
      const fragLen = readUInt24BE(buf, off + 9)
      if (off + 12 + fragLen > buf.byteLength) break

      const fragBody = buf.subarray(off + 12, off + 12 + fragLen)
      off += 12 + fragLen

      let fullBody = null
      if (fragOff === 0 && fragLen === msgLen) {
        fullBody = fragBody
      } else {
        let entry = this.handshakeFragments.get(msgSeq)
        if (!entry) {
          entry = { msgType, msgLen, buf: Buffer.alloc(msgLen), received: 0 }
          this.handshakeFragments.set(msgSeq, entry)
        }
        fragBody.copy(entry.buf, fragOff)
        entry.received += fragLen
        if (entry.received >= msgLen) {
          this.handshakeFragments.delete(msgSeq)
          fullBody = entry.buf
        }
      }

      if (fullBody) {
        const fullHs = wrapHandshake(msgType, msgSeq, fullBody)
        if (this.role === 'server') {
          this._onServerHandshakeMessage(msgType, msgSeq, fullBody, fullHs)
        } else {
          this._onClientHandshakeMessage(msgType, msgSeq, fullBody, fullHs)
        }
      }
    }
  }

  _onServerHandshakeMessage (msgType, msgSeq, body, rawHs) {
    if (msgType === HANDSHAKE_CLIENT_HELLO) {
      const parsed = parseClientHello(body)
      if (!parsed) return

      // Stateless cookie exchange (Flight 1 -> Flight 2) when cookie is empty
      if (parsed.cookie.length === 0) {
        const hvrBody = Buffer.allocUnsafe(3 + this.cookie.length)
        hvrBody[0] = 0xfe
        hvrBody[1] = 0xfd
        hvrBody[2] = this.cookie.length
        this.cookie.copy(hvrBody, 3)
        const hvr = wrapHandshake(HANDSHAKE_HELLO_VERIFY_REQUEST, 0, hvrBody)
        this._sendRecord(CONTENT_HANDSHAKE, 0, hvr)
        return
      }

      // Flight 3 -> Flight 4
      this.clientRandom = parsed.random
      this.serverRandom = crypto.randomBytes(32)
      this.useExtendedMasterSecret = parsed.extendedMasterSecret
      this.selectedSrtpProfile = parsed.srtpProfile
      this.transcript = [rawHs]
      this.handshakeSeqOut = 1

      const serverHello = wrapHandshake(
        HANDSHAKE_SERVER_HELLO,
        this.handshakeSeqOut++,
        this._buildServerHelloBody()
      )
      const certificate = wrapHandshake(
        HANDSHAKE_CERTIFICATE,
        this.handshakeSeqOut++,
        this._buildCertificateBody()
      )
      const serverKeyExchange = wrapHandshake(
        HANDSHAKE_SERVER_KEY_EXCHANGE,
        this.handshakeSeqOut++,
        this._buildServerKeyExchangeBody()
      )
      const serverHelloDone = wrapHandshake(
        HANDSHAKE_SERVER_HELLO_DONE,
        this.handshakeSeqOut++,
        Buffer.alloc(0)
      )

      this.transcript.push(serverHello, certificate, serverKeyExchange, serverHelloDone)

      // Pack Flight 4 records into a single UDP datagram for fast 1-RTT setup
      const flight4 = Buffer.concat([
        this._packRecord(CONTENT_HANDSHAKE, 0, serverHello),
        this._packRecord(CONTENT_HANDSHAKE, 0, certificate),
        this._packRecord(CONTENT_HANDSHAKE, 0, serverKeyExchange),
        this._packRecord(CONTENT_HANDSHAKE, 0, serverHelloDone)
      ])
      this._sendRaw(flight4)
      return
    }

    if (msgType === HANDSHAKE_CERTIFICATE || msgType === HANDSHAKE_CERTIFICATE_VERIFY) {
      this.transcript.push(rawHs)
      return
    }

    if (msgType === HANDSHAKE_CLIENT_KEY_EXCHANGE) {
      if (body.length < 2) return
      const pubLen = body[0]
      const clientPub = body.subarray(1, 1 + pubLen)
      this.transcript.push(rawHs)
      this._deriveKeys(clientPub)
      return
    }

    if (msgType === HANDSHAKE_FINISHED) {
      if (!this.masterSecret) return
      this.transcript.push(rawHs)

      const verifyData = prfSha256(
        this.masterSecret,
        'server finished',
        this._transcriptHash(),
        12
      )
      const finishedHs = wrapHandshake(HANDSHAKE_FINISHED, this.handshakeSeqOut++, verifyData)
      this.transcript.push(finishedHs)

      const ccsRec = this._packRecord(CONTENT_CHANGE_CIPHER_SPEC, 0, Buffer.from([0x01]))
      this.epoch = 1
      const finRec = this._packEncryptedRecord(CONTENT_HANDSHAKE, finishedHs)
      this._sendRaw(Buffer.concat([ccsRec, finRec]))

      if (!this.connected) {
        this.connected = true
        this.emit('connect')
      }
    }
  }

  _onClientHandshakeMessage (msgType, msgSeq, body, rawHs) {
    if (msgType === HANDSHAKE_HELLO_VERIFY_REQUEST) {
      if (body.length < 3) return
      const cookieLen = body[2]
      const cookie = Buffer.from(body.subarray(3, 3 + cookieLen))
      this.startClient(cookie)
      return
    }

    if (msgType === HANDSHAKE_SERVER_HELLO) {
      this.serverRandom = Buffer.from(body.subarray(2, 34))
      const sidLen = body[34]
      let off = 35 + sidLen + 2 + 1
      this.useExtendedMasterSecret = false
      if (off + 2 <= body.length) {
        const extLen = body.readUInt16BE(off)
        off += 2
        const end = off + extLen
        while (off + 4 <= end && end <= body.length) {
          const et = body.readUInt16BE(off)
          const el = body.readUInt16BE(off + 2)
          if (et === 0x0017) this.useExtendedMasterSecret = true
          off += 4 + el
        }
      }
      this.transcript.push(rawHs)
      return
    }

    if (msgType === HANDSHAKE_CERTIFICATE || msgType === HANDSHAKE_CERTIFICATE_REQUEST) {
      this.transcript.push(rawHs)
      return
    }

    if (msgType === HANDSHAKE_SERVER_KEY_EXCHANGE) {
      this.transcript.push(rawHs)
      if (body.length < 4) return
      const pubLen = body[3]
      this._serverEcdhPub = Buffer.from(body.subarray(4, 4 + pubLen))
      return
    }

    if (msgType === HANDSHAKE_SERVER_HELLO_DONE) {
      this.transcript.push(rawHs)
      if (!this._serverEcdhPub) return

      const localPub = this.ecdh.getPublicKey()
      const ckeBody = Buffer.allocUnsafe(1 + localPub.length)
      ckeBody[0] = localPub.length
      localPub.copy(ckeBody, 1)
      const ckeHs = wrapHandshake(HANDSHAKE_CLIENT_KEY_EXCHANGE, this.handshakeSeqOut++, ckeBody)
      this.transcript.push(ckeHs)

      this._deriveKeys(this._serverEcdhPub)

      const verifyData = prfSha256(
        this.masterSecret,
        'client finished',
        this._transcriptHash(),
        12
      )
      const finHs = wrapHandshake(HANDSHAKE_FINISHED, this.handshakeSeqOut++, verifyData)
      this.transcript.push(finHs)

      const ckeRec = this._packRecord(CONTENT_HANDSHAKE, 0, ckeHs)
      const ccsRec = this._packRecord(CONTENT_CHANGE_CIPHER_SPEC, 0, Buffer.from([0x01]))
      this.epoch = 1
      const finRec = this._packEncryptedRecord(CONTENT_HANDSHAKE, finHs)
      this._sendRaw(Buffer.concat([ckeRec, ccsRec, finRec]))
      return
    }

    if (msgType === HANDSHAKE_FINISHED) {
      this.transcript.push(rawHs)
      if (!this.connected) {
        this.connected = true
        this.emit('connect')
      }
    }
  }

  _buildServerHelloBody () {
    const extParts = [
      Buffer.from([0xff, 0x01, 0x00, 0x01, 0x00]), // renegotiation_info
      Buffer.from([0x00, 0x0b, 0x00, 0x02, 0x01, 0x00]) // ec_point_formats: uncompressed
    ]
    if (this.useExtendedMasterSecret) {
      extParts.push(Buffer.from([0x00, 0x17, 0x00, 0x00]))
    }
    if (this.selectedSrtpProfile) {
      const srtp = Buffer.from([0x00, 0x0e, 0x00, 0x05, 0x00, 0x02, 0x00, 0x00, 0x00])
      srtp.writeUInt16BE(this.selectedSrtpProfile, 6)
      extParts.push(srtp)
    }
    const exts = Buffer.concat(extParts)

    const out = Buffer.allocUnsafe(2 + 32 + 1 + 2 + 1 + 2 + exts.length)
    let off = 0
    out[off++] = 0xfe
    out[off++] = 0xfd
    this.serverRandom.copy(out, off)
    off += 32
    out[off++] = 0 // session_id len = 0
    out.writeUInt16BE(CIPHER_ECDHE_ECDSA_AES128_GCM_SHA256, off)
    off += 2
    out[off++] = 0 // compression_method = null
    out.writeUInt16BE(exts.length, off)
    off += 2
    exts.copy(out, off)
    return out
  }

  _buildCertificateBody () {
    const der = this.cert.certDer
    const out = Buffer.allocUnsafe(6 + der.length)
    writeUInt24BE(out, 3 + der.length, 0)
    writeUInt24BE(out, der.length, 3)
    der.copy(out, 6)
    return out
  }

  _buildServerKeyExchangeBody () {
    const pub = this.ecdh.getPublicKey()
    const params = Buffer.allocUnsafe(4 + pub.length)
    params[0] = 0x03 // named_curve
    params.writeUInt16BE(NAMED_CURVE_P256, 1)
    params[3] = pub.length
    pub.copy(params, 4)

    const toSign = Buffer.concat([this.clientRandom, this.serverRandom, params])
    const sig = crypto.sign('sha256', toSign, this.cert.keyPem)

    const out = Buffer.allocUnsafe(params.length + 4 + sig.length)
    params.copy(out, 0)
    let off = params.length
    out[off++] = 0x04 // sha256
    out[off++] = 0x03 // ecdsa
    out.writeUInt16BE(sig.length, off)
    off += 2
    sig.copy(out, off)
    return out
  }

  _deriveKeys (remotePub) {
    const preMaster = this.ecdh.computeSecret(remotePub)
    if (this.useExtendedMasterSecret) {
      this.masterSecret = prfSha256(
        preMaster,
        'extended master secret',
        this._transcriptHash(),
        48
      )
    } else {
      this.masterSecret = prfSha256(
        preMaster,
        'master secret',
        Buffer.concat([this.clientRandom, this.serverRandom]),
        48
      )
    }

    const keyBlock = prfSha256(
      this.masterSecret,
      'key expansion',
      Buffer.concat([this.serverRandom, this.clientRandom]),
      40
    )

    const clientWriteKey = keyBlock.subarray(0, 16)
    const serverWriteKey = keyBlock.subarray(16, 32)
    const clientWriteIV = keyBlock.subarray(32, 36)
    const serverWriteIV = keyBlock.subarray(36, 40)

    if (this.role === 'server') {
      this.localWriteKey = serverWriteKey
      this.remoteWriteKey = clientWriteKey
      this.localWriteIV = serverWriteIV
      this.remoteWriteIV = clientWriteIV
    } else {
      this.localWriteKey = clientWriteKey
      this.remoteWriteKey = serverWriteKey
      this.localWriteIV = clientWriteIV
      this.remoteWriteIV = serverWriteIV
    }
  }

  _transcriptHash () {
    const h = crypto.createHash('sha256')
    for (const msg of this.transcript) h.update(msg)
    return h.digest()
  }

  _packRecord (contentType, epoch, payload) {
    const seq = this.recordSeq[epoch]++
    return wrapRecord(contentType, epoch, seq, payload)
  }

  _sendRecord (contentType, epoch, payload) {
    this._sendRaw(this._packRecord(contentType, epoch, payload))
  }

  _packEncryptedRecord (contentType, plaintext) {
    const epoch = 1
    const seq = this.recordSeq[epoch]++
    const explicitNonce = Buffer.allocUnsafe(8)
    explicitNonce.writeUInt16BE(epoch, 0)
    writeUInt48BE(explicitNonce, seq, 2)

    const nonce = Buffer.concat([this.localWriteIV, explicitNonce])
    const aad = Buffer.allocUnsafe(13)
    explicitNonce.copy(aad, 0)
    aad[8] = contentType
    aad[9] = 0xfe
    aad[10] = 0xfd
    aad.writeUInt16BE(plaintext.length, 11)

    const cipher = crypto.createCipheriv('aes-128-gcm', this.localWriteKey, nonce)
    cipher.setAAD(aad)
    const enc = Buffer.concat([cipher.update(plaintext), cipher.final()])
    const tag = cipher.getAuthTag()

    const body = Buffer.concat([explicitNonce, enc, tag])
    return wrapRecord(contentType, epoch, seq, body)
  }

  _decryptRecord (contentType, versionHi, versionLo, seqBytes, fragment) {
    if (fragment.length < 24) return null
    const explicitNonce = fragment.subarray(0, 8)
    const ciphertext = fragment.subarray(8, fragment.length - 16)
    const tag = fragment.subarray(fragment.length - 16)

    const nonce = Buffer.concat([this.remoteWriteIV, explicitNonce])
    const aad = Buffer.allocUnsafe(13)
    seqBytes.copy(aad, 0)
    aad[8] = contentType
    aad[9] = versionHi
    aad[10] = versionLo
    aad.writeUInt16BE(ciphertext.length, 11)

    try {
      const decipher = crypto.createDecipheriv('aes-128-gcm', this.remoteWriteKey, nonce)
      decipher.setAAD(aad)
      decipher.setAuthTag(tag)
      return Buffer.concat([decipher.update(ciphertext), decipher.final()])
    } catch {
      return null
    }
  }

  send (appData) {
    if (this.closed || !this.connected) return
    const rec = this._packEncryptedRecord(CONTENT_APPLICATION_DATA, appData)
    this._sendRaw(rec)
  }

  close () {
    this.closed = true
  }
}

function parseClientHello (body) {
  if (body.length < 38) return null
  const random = Buffer.from(body.subarray(2, 34))
  let off = 34
  const sessionIdLen = body[off++]
  off += sessionIdLen
  if (off >= body.length) return null
  const cookieLen = body[off++]
  const cookie = Buffer.from(body.subarray(off, off + cookieLen))
  off += cookieLen
  if (off + 2 > body.length) return null
  const csLen = body.readUInt16BE(off)
  off += 2 + csLen
  if (off >= body.length) return null
  const compLen = body[off++]
  off += compLen

  let extendedMasterSecret = false
  let srtpProfile = 0
  if (off + 2 <= body.length) {
    const extTotal = body.readUInt16BE(off)
    off += 2
    const end = Math.min(body.length, off + extTotal)
    while (off + 4 <= end) {
      const extType = body.readUInt16BE(off)
      const extLen = body.readUInt16BE(off + 2)
      const valStart = off + 4
      if (valStart + extLen > end) break
      if (extType === 0x0017) {
        extendedMasterSecret = true
      } else if (extType === 0x000e && extLen >= 4) {
        const profilesLen = body.readUInt16BE(valStart)
        if (profilesLen >= 2) {
          srtpProfile = body.readUInt16BE(valStart + 2)
        }
      }
      off = valStart + extLen
    }
  }

  return { random, cookie, extendedMasterSecret, srtpProfile }
}

module.exports = { DtlsEndpoint }
