'use strict'

const crypto = require('crypto')
const { EventEmitter } = require('events')

// Castagnoli CRC-32C lookup table (polynomial 0x82f63b78) required by RFC 4960 SCTP
const CRC32C_TABLE = (() => {
  const table = new Uint32Array(256)
  for (let i = 0; i < 256; i++) {
    let crc = i
    for (let j = 0; j < 8; j++) {
      crc = (crc & 1) ? ((crc >>> 1) ^ 0x82f63b78) : (crc >>> 1)
    }
    table[i] = crc >>> 0
  }
  return table
})()

function crc32c (buf) {
  let crc = 0xffffffff
  for (let i = 0; i < buf.length; i++) {
    crc = CRC32C_TABLE[(crc ^ buf[i]) & 0xff] ^ (crc >>> 8)
  }
  return (crc ^ 0xffffffff) >>> 0
}

const CHUNK_DATA = 0
const CHUNK_INIT = 1
const CHUNK_INIT_ACK = 2
const CHUNK_SACK = 3
const CHUNK_HEARTBEAT = 4
const CHUNK_HEARTBEAT_ACK = 5
const CHUNK_COOKIE_ECHO = 10
const CHUNK_COOKIE_ACK = 11
const CHUNK_FORWARD_TSN = 192

const PPID_DCEP = 50
const PPID_STRING = 51
const PPID_BINARY = 53

const DCEP_DATA_CHANNEL_ACK = 0x02
const DCEP_DATA_CHANNEL_OPEN = 0x03

// Zero-dependency SCTP + WebRTC DataChannel endpoint over DTLS
class SctpEndpoint extends EventEmitter {
  constructor ({ role = 'server', port = 5000, send }) {
    super()
    this.role = role
    this.localPort = port
    this.remotePort = port
    this._sendDtls = send

    this.localTag = crypto.randomBytes(4).readUInt32BE(0) || 1
    this.remoteTag = 0
    this.localTsn = crypto.randomBytes(4).readUInt32BE(0)
    this.lastRemoteTsn = 0
    this.open = false
    this.closed = false
    this.cookie = crypto.randomBytes(8)
  }

  // Start active SCTP client association (sends INIT chunk)
  startClient () {
    if (this.closed) return
    const initBody = Buffer.allocUnsafe(16 + 4)
    initBody.writeUInt32BE(this.localTag, 0)
    initBody.writeUInt32BE(1048576, 4) // a_rwnd
    initBody.writeUInt16BE(65535, 8) // outbound streams
    initBody.writeUInt16BE(65535, 10) // inbound streams
    initBody.writeUInt32BE(this.localTsn, 12)
    // Forward-TSN-Supported parameter (0xc000, len 4)
    initBody.writeUInt16BE(0xc000, 16)
    initBody.writeUInt16BE(4, 18)

    this._sendPacket(0, this._packChunk(CHUNK_INIT, 0, initBody))
  }

  // Feed a decrypted SCTP packet from DTLS ApplicationData
  feedPacket (buf) {
    if (this.closed || buf.byteLength < 12) return
    const srcPort = buf.readUInt16BE(0)
    this.remotePort = srcPort

    let off = 12
    while (off + 4 <= buf.byteLength) {
      const chunkType = buf[off]
      const chunkFlags = buf[off + 1]
      const chunkLen = buf.readUInt16BE(off + 2)
      if (chunkLen < 4 || off + chunkLen > buf.byteLength) break

      const chunkBody = buf.subarray(off + 4, off + chunkLen)
      off += (chunkLen + 3) & ~3

      this._onChunk(chunkType, chunkFlags, chunkBody)
    }
  }

  _onChunk (type, flags, body) {
    if (type === CHUNK_INIT) {
      if (body.byteLength < 16) return
      this.remoteTag = body.readUInt32BE(0)
      const remoteInitTsn = body.readUInt32BE(12)
      this.lastRemoteTsn = (remoteInitTsn - 1) >>> 0

      // Build INIT_ACK with State Cookie parameter (type 7) and Forward-TSN-Supported (0xc000)
      const initAckBody = Buffer.allocUnsafe(16 + 12 + 4)
      initAckBody.writeUInt32BE(this.localTag, 0)
      initAckBody.writeUInt32BE(1048576, 4)
      initAckBody.writeUInt16BE(65535, 8)
      initAckBody.writeUInt16BE(65535, 10)
      initAckBody.writeUInt32BE(this.localTsn, 12)
      // State Cookie param (type 0x0007, len 12)
      initAckBody.writeUInt16BE(0x0007, 16)
      initAckBody.writeUInt16BE(12, 18)
      this.cookie.copy(initAckBody, 20)
      // Forward-TSN-Supported (type 0xc000, len 4)
      initAckBody.writeUInt16BE(0xc000, 28)
      initAckBody.writeUInt16BE(4, 30)

      this._sendPacket(this.remoteTag, this._packChunk(CHUNK_INIT_ACK, 0, initAckBody))
      return
    }

    if (type === CHUNK_INIT_ACK) {
      if (body.byteLength < 16) return
      this.remoteTag = body.readUInt32BE(0)
      const remoteInitTsn = body.readUInt32BE(12)
      this.lastRemoteTsn = (remoteInitTsn - 1) >>> 0

      // Extract State Cookie parameter (0x0007)
      let cookieVal = this.cookie
      let pOff = 16
      while (pOff + 4 <= body.byteLength) {
        const pType = body.readUInt16BE(pOff)
        const pLen = body.readUInt16BE(pOff + 2)
        if (pLen < 4 || pOff + pLen > body.byteLength) break
        if (pType === 0x0007) {
          cookieVal = body.subarray(pOff + 4, pOff + pLen)
          break
        }
        pOff += (pLen + 3) & ~3
      }

      this._sendPacket(this.remoteTag, this._packChunk(CHUNK_COOKIE_ECHO, 0, cookieVal))
      return
    }

    if (type === CHUNK_COOKIE_ECHO) {
      this._sendPacket(this.remoteTag, this._packChunk(CHUNK_COOKIE_ACK, 0, Buffer.alloc(0)))
      if (!this.open) {
        this.open = true
        this.emit('open')
      }
      return
    }

    if (type === CHUNK_COOKIE_ACK) {
      if (!this.open) {
        this.open = true
        this.emit('open')
      }
      return
    }

    if (type === CHUNK_HEARTBEAT) {
      this._sendPacket(this.remoteTag, this._packChunk(CHUNK_HEARTBEAT_ACK, 0, body))
      return
    }

    if (type === CHUNK_FORWARD_TSN) {
      if (body.byteLength >= 4) {
        this.lastRemoteTsn = body.readUInt32BE(0)
        this._sendSack()
      }
      return
    }

    if (type === CHUNK_DATA) {
      if (body.byteLength < 12) return
      const tsn = body.readUInt32BE(0)
      const streamId = body.readUInt16BE(4)
      const ppid = body.readUInt32BE(8)
      const userData = body.subarray(12)

      this.lastRemoteTsn = tsn
      this._sendSack()

      let fullData = null
      const bBit = (flags & 0x02) !== 0
      const eBit = (flags & 0x01) !== 0

      if (bBit && eBit) {
        fullData = Buffer.from(userData)
      } else if (bBit && !eBit) {
        this._fragChunks = [Buffer.from(userData)]
        return
      } else if (!bBit && !eBit) {
        if (this._fragChunks) this._fragChunks.push(Buffer.from(userData))
        return
      } else if (!bBit && eBit) {
        if (this._fragChunks) {
          this._fragChunks.push(Buffer.from(userData))
          fullData = Buffer.concat(this._fragChunks)
          this._fragChunks = null
        }
      }
      if (!fullData) return

      if (ppid === PPID_DCEP && fullData.byteLength > 0 && fullData[0] === DCEP_DATA_CHANNEL_OPEN) {
        this.sendData(Buffer.from([DCEP_DATA_CHANNEL_ACK]), streamId, PPID_DCEP)
        return
      }

      if (ppid === PPID_BINARY || ppid === PPID_STRING) {
        this.emit('message', fullData, streamId)
      }
    }
  }

  _sendSack () {
    const sackBody = Buffer.alloc(12)
    sackBody.writeUInt32BE(this.lastRemoteTsn >>> 0, 0)
    sackBody.writeUInt32BE(1048576, 4) // a_rwnd
    sackBody.writeUInt16BE(0, 8) // num gap ack blocks
    sackBody.writeUInt16BE(0, 10) // num dup tsns
    this._sendPacket(this.remoteTag, this._packChunk(CHUNK_SACK, 0, sackBody))
  }

  // Send an unordered, unfragmented DataChannel binary datagram (flags = 0x07: U|B|E)
  sendData (payload, streamId = 0, ppid = PPID_BINARY) {
    if (this.closed || !this.open) return
    const maxFrag = 1000
    let off = 0
    const total = payload.byteLength

    while (off < total || total === 0) {
      const end = Math.min(off + maxFrag, total)
      const slice = payload.subarray(off, end)
      const isFirst = off === 0
      const isLast = end >= total
      const flags = 0x04 | (isFirst ? 0x02 : 0x00) | (isLast ? 0x01 : 0x00)
      off = end

      const tsn = this.localTsn
      this.localTsn = (this.localTsn + 1) >>> 0

      const body = Buffer.allocUnsafe(12 + slice.byteLength)
      body.writeUInt32BE(tsn, 0)
      body.writeUInt16BE(streamId & 0xffff, 4)
      body.writeUInt16BE(0, 6)
      body.writeUInt32BE(ppid >>> 0, 8)
      slice.copy(body, 12)

      this._sendPacket(this.remoteTag, this._packChunk(CHUNK_DATA, flags, body))
      if (total === 0) break
    }
  }

  _packChunk (type, flags, body) {
    const chunkLen = 4 + body.byteLength
    const paddedLen = (chunkLen + 3) & ~3
    const out = Buffer.alloc(paddedLen)
    out[0] = type
    out[1] = flags
    out.writeUInt16BE(chunkLen, 2)
    body.copy(out, 4)
    return out
  }

  _sendPacket (verificationTag, chunkBuf) {
    if (this.closed) return
    const pkt = Buffer.allocUnsafe(12 + chunkBuf.byteLength)
    pkt.writeUInt16BE(this.localPort, 0)
    pkt.writeUInt16BE(this.remotePort, 2)
    pkt.writeUInt32BE(verificationTag >>> 0, 4)
    pkt.writeUInt32LE(0, 8)
    chunkBuf.copy(pkt, 12)

    const sum = crc32c(pkt)
    pkt.writeUInt32LE(sum, 8)
    this._sendDtls(pkt)
  }

  close () {
    this.closed = true
  }
}

module.exports = { SctpEndpoint, crc32c }
