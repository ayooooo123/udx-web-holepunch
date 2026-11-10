'use strict'

const crypto = require('crypto')
const zlib = require('zlib')

const STUN_COOKIE = 0x2112a442
const BINDING_REQUEST = 0x0001
const BINDING_RESPONSE = 0x0101
const ATTR_USERNAME = 0x0006
const ATTR_MESSAGE_INTEGRITY = 0x0008
const ATTR_XOR_MAPPED_ADDRESS = 0x0020
const ATTR_ICE_CONTROLLED = 0x8029
const ATTR_ICE_CONTROLLING = 0x802a
const ATTR_USE_CANDIDATE = 0x0025
const ATTR_PRIORITY = 0x0024
const ATTR_FINGERPRINT = 0x8028
const FINGERPRINT_XOR = 0x5354554e

// Parse an incoming STUN packet and extract method, transactionId, username, and XOR-MAPPED-ADDRESS
function parseStun (buf) {
  if (!buf || buf.byteLength < 20) return null
  if ((buf[0] & 0xc0) !== 0x00) return null
  if (buf.readUInt32BE(4) !== STUN_COOKIE) return null

  const type = buf.readUInt16BE(0)
  const msgLen = buf.readUInt16BE(2)
  if (20 + msgLen > buf.byteLength) return null

  const transactionId = Buffer.from(buf.subarray(8, 20))
  let username = null
  let xorMappedAddress = null

  let off = 20
  const end = 20 + msgLen
  while (off + 4 <= end) {
    const attrType = buf.readUInt16BE(off)
    const attrLen = buf.readUInt16BE(off + 2)
    const valStart = off + 4
    const valEnd = valStart + attrLen
    if (valEnd > end) break

    if (attrType === ATTR_USERNAME) {
      username = buf.subarray(valStart, valEnd).toString('utf8')
    } else if (attrType === ATTR_XOR_MAPPED_ADDRESS && attrLen >= 8 && buf[valStart + 1] === 0x01) {
      const port = buf.readUInt16BE(valStart + 2) ^ (STUN_COOKIE >>> 16)
      const ipU32 = (buf.readUInt32BE(valStart + 4) ^ STUN_COOKIE) >>> 0
      const host = [
        (ipU32 >>> 24) & 0xff,
        (ipU32 >>> 16) & 0xff,
        (ipU32 >>> 8) & 0xff,
        ipU32 & 0xff
      ].join('.')
      xorMappedAddress = { host, port }
    }

    off = valStart + ((attrLen + 3) & ~3)
  }

  return { type, transactionId, username, xorMappedAddress }
}

// Build an RFC 5389 / RFC 8445 STUN Binding Success Response with XOR-MAPPED-ADDRESS, optional HMAC-SHA1, and CRC32 FINGERPRINT
function buildBindingResponse ({ transactionId, host, port, icePwd = null }) {
  const ipParts = (host === '::1' || host === '::' ? '127.0.0.1' : host).split('.').map(Number)
  const ipU32 = (
    ((ipParts[0] || 127) << 24) |
    ((ipParts[1] || 0) << 16) |
    ((ipParts[2] || 0) << 8) |
    (ipParts[3] || 1)
  ) >>> 0

  const xorPort = (port ^ (STUN_COOKIE >>> 16)) & 0xffff
  const xorIp = (ipU32 ^ STUN_COOKIE) >>> 0

  const hasIntegrity = typeof icePwd === 'string' && icePwd.length > 0
  const totalLen = 20 + 12 + (hasIntegrity ? 24 : 0) + 8
  const buf = Buffer.alloc(totalLen)

  buf.writeUInt16BE(BINDING_RESPONSE, 0)
  buf.writeUInt32BE(STUN_COOKIE, 4)
  transactionId.copy(buf, 8, 0, 12)

  // Attribute 1: XOR-MAPPED-ADDRESS (type 0x0020, len 8)
  let off = 20
  buf.writeUInt16BE(ATTR_XOR_MAPPED_ADDRESS, off)
  buf.writeUInt16BE(8, off + 2)
  buf[off + 4] = 0x00
  buf[off + 5] = 0x01 // IPv4
  buf.writeUInt16BE(xorPort, off + 6)
  buf.writeUInt32BE(xorIp, off + 8)
  off += 12

  if (hasIntegrity) {
    // RFC 5389 S15.4: header length during HMAC calculation includes MESSAGE-INTEGRITY (12 + 24 = 36)
    buf.writeUInt16BE(12 + 24, 2)
    const hmac = crypto
      .createHmac('sha1', Buffer.from(icePwd, 'utf8'))
      .update(buf.subarray(0, off))
      .digest()
    buf.writeUInt16BE(ATTR_MESSAGE_INTEGRITY, off)
    buf.writeUInt16BE(20, off + 2)
    hmac.copy(buf, off + 4)
    off += 24
  }

  // RFC 5389 S15.5: header length during FINGERPRINT calculation includes FINGERPRINT itself
  buf.writeUInt16BE(off - 20 + 8, 2)
  const crc = (zlib.crc32(buf.subarray(0, off)) ^ FINGERPRINT_XOR) >>> 0
  buf.writeUInt16BE(ATTR_FINGERPRINT, off)
  buf.writeUInt16BE(4, off + 2)
  buf.writeUInt32BE(crc, off + 4)

  return buf
}

// Build an outbound STUN Binding Request so our lightweight Node ICE client can punch and authenticate
function buildBindingRequest ({
  localUfrag,
  remoteUfrag,
  remotePwd,
  transactionId = crypto.randomBytes(12)
}) {
  const usernameBuf = Buffer.from(`${remoteUfrag}:${localUfrag}`, 'utf8')
  const paddedUserLen = (usernameBuf.length + 3) & ~3
  const userAttrLen = 4 + paddedUserLen
  // Include PRIORITY (8), ICE-CONTROLLING (12), USE-CANDIDATE (4), MESSAGE-INTEGRITY (24), FINGERPRINT (8)
  const bodyBeforeIntegrity = userAttrLen + 8 + 12 + 4
  const totalLen = 20 + bodyBeforeIntegrity + 24 + 8
  const buf = Buffer.alloc(totalLen)

  buf.writeUInt16BE(BINDING_REQUEST, 0)
  buf.writeUInt32BE(STUN_COOKIE, 4)
  transactionId.copy(buf, 8, 0, 12)

  let off = 20
  // USERNAME
  buf.writeUInt16BE(ATTR_USERNAME, off)
  buf.writeUInt16BE(usernameBuf.length, off + 2)
  usernameBuf.copy(buf, off + 4)
  off += userAttrLen

  // PRIORITY
  buf.writeUInt16BE(ATTR_PRIORITY, off)
  buf.writeUInt16BE(4, off + 2)
  buf.writeUInt32BE(0x6e0001ff, off + 4)
  off += 8

  // ICE-CONTROLLING
  buf.writeUInt16BE(ATTR_ICE_CONTROLLING, off)
  buf.writeUInt16BE(8, off + 2)
  buf.writeUInt32BE(0x12345678, off + 4)
  buf.writeUInt32BE(0x9abcdef0, off + 8)
  off += 12

  // USE-CANDIDATE
  buf.writeUInt16BE(ATTR_USE_CANDIDATE, off)
  buf.writeUInt16BE(0, off + 2)
  off += 4

  // MESSAGE-INTEGRITY
  buf.writeUInt16BE(off - 20 + 24, 2)
  const hmac = crypto
    .createHmac('sha1', Buffer.from(remotePwd, 'utf8'))
    .update(buf.subarray(0, off))
    .digest()
  buf.writeUInt16BE(ATTR_MESSAGE_INTEGRITY, off)
  buf.writeUInt16BE(20, off + 2)
  hmac.copy(buf, off + 4)
  off += 24

  // FINGERPRINT
  buf.writeUInt16BE(off - 20 + 8, 2)
  const crc = (zlib.crc32(buf.subarray(0, off)) ^ FINGERPRINT_XOR) >>> 0
  buf.writeUInt16BE(ATTR_FINGERPRINT, off)
  buf.writeUInt16BE(4, off + 2)
  buf.writeUInt32BE(crc, off + 4)

  return buf
}

module.exports = {
  BINDING_REQUEST,
  BINDING_RESPONSE,
  parseStun,
  buildBindingResponse,
  buildBindingRequest
}
