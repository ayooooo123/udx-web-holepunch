'use strict'

const b4a = require('b4a')

// Default outer WebRTC ICE-Lite credentials; real E2E auth lives inside Holepunch Noise SecretStream
const DEFAULT_ICE_UFRAG = 'udxweb'
const DEFAULT_ICE_PWD = 'udxwebstaticpassword1234'

// Pre-generated 10-year ECDSA P-256 certificate so WebBridgeUDX and BrowserUDX work synchronously with zero external deps
const DEFAULT_CERT_PEM = [
  '-----BEGIN CERTIFICATE-----',
  'MIIBgzCCASmgAwIBAgIJAP9NICVjU518MAoGCCqGSM49BAMCMEUxCzAJBgNVBAYT',
  'AkFVMRMwEQYDVQQIEwpTb21lLVN0YXRlMSEwHwYDVQQKExhJbnRlcm5ldCBXaWRn',
  'aXRzIFB0eSBMdGQwHhcNMjYxMTEwMTcyNzQwWhcNMzYxMTEwMTcyNzQwWjBFMQsw',
  'CQYDVQQGEwJBVTETMBEGA1UECBMKU29tZS1TdGF0ZTEhMB8GA1UEChMYSW50ZXJu',
  'ZXQgV2lkZ2l0cyBQdHkgTHRkMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEiCPh',
  'zHQQ3kGRvXNIc2eAanUlRGr+geyN8UCOIcCnmVQxzpzze7hOtf31PpxSvMPJdWHH',
  'qXZaox3ovUGGo4tY5KMCMAAwCgYIKoZIzj0EAwIDSAAwRQIga6PCaMLaJhnkO2sf',
  'UjLS7zE7sEFEpsWZ60mR32RfbRsCIQCtcegSknvMUmSSzj29EPUssE8JOgERZm41',
  'A1RdCYBsIA==',
  '-----END CERTIFICATE-----'
].join('\n')

const DEFAULT_KEY_PEM = [
  '-----BEGIN PRIVATE KEY-----',
  'MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQglZvn7wBB8V+hZvaR',
  'MKaNyL+zbsMLOz25VDs+9MJTWXShRANCAASII+HMdBDeQZG9c0hzZ4BqdSVEav6B',
  '7I3xQI4hwKeZVDHOnPN7uE61/fU+nFK8w8l1YcepdlqjHei9QYaji1jk',
  '-----END PRIVATE KEY-----'
].join('\n')

const DEFAULT_FINGERPRINT =
  '62:F9:D7:28:50:92:75:EC:31:CB:EB:CF:27:87:C3:77:A4:9C:81:FD:AE:88:C8:7A:2A:30:EC:6F:A1:03:3A:14'

function pemToDer (certPem) {
  const b64 = certPem
    .replace(/-----BEGIN CERTIFICATE-----/g, '')
    .replace(/-----END CERTIFICATE-----/g, '')
    .replace(/\s+/g, '')
  return b4a.from(b64, 'base64')
}

function pemToFingerprint (certPem) {
  if (certPem === DEFAULT_CERT_PEM) return DEFAULT_FINGERPRINT
  const crypto = require('crypto')
  const der = pemToDer(certPem)
  const digest = crypto.createHash('sha256').update(der).digest('hex').toUpperCase()
  return digest.match(/.{2}/g).join(':')
}

const DEFAULT_CERT = {
  certPem: DEFAULT_CERT_PEM,
  keyPem: DEFAULT_KEY_PEM,
  get certDer () {
    return pemToDer(DEFAULT_CERT_PEM)
  },
  fingerprint: DEFAULT_FINGERPRINT
}

// Forge a zero-signaling ice-lite SDP Answer locally so the browser squirts STUN + DTLS straight at host:port
function buildIceLiteSdp ({
  host,
  port,
  fingerprint = DEFAULT_CERT.fingerprint,
  ufrag = DEFAULT_ICE_UFRAG,
  pwd = DEFAULT_ICE_PWD,
  sctpPort = 5000,
  mid = '0'
}) {
  return [
    'v=0',
    `o=- 0 2 IN IP4 ${host}`,
    's=-',
    't=0 0',
    `a=group:BUNDLE ${mid}`,
    'a=ice-lite',
    `m=application ${port} UDP/DTLS/SCTP webrtc-datachannel`,
    `c=IN IP4 ${host}`,
    `a=ice-ufrag:${ufrag}`,
    `a=ice-pwd:${pwd}`,
    `a=fingerprint:sha-256 ${fingerprint}`,
    'a=setup:passive',
    `a=mid:${mid}`,
    `a=sctp-port:${sctpPort}`,
    'a=max-message-size:65536',
    `a=candidate:1 1 udp 2130706431 ${host} ${port} typ host`,
    'a=end-of-candidates',
    ''
  ].join('\r\n')
}

module.exports = {
  DEFAULT_ICE_UFRAG,
  DEFAULT_ICE_PWD,
  DEFAULT_CERT,
  pemToDer,
  pemToFingerprint,
  buildIceLiteSdp
}
