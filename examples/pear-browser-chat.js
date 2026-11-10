'use strict'

const http = require('http')
const fs = require('fs')
const path = require('path')
const HyperDHT = require('hyperdht')
const { WebBridgeUDX } = require('../index')

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

  const publicDir = path.join(__dirname, '..', 'public')
  const server = http.createServer((req, res) => {
    const urlPath = req.url.split('?')[0]
    const file = urlPath === '/bundle.js' ? 'bundle.js' : 'index.html'
    const contentType =
      file === 'bundle.js' ? 'application/javascript; charset=utf-8' : 'text/html; charset=utf-8'
    try {
      const body = fs.readFileSync(path.join(publicDir, file))
      res.writeHead(200, { 'content-type': contentType })
      res.end(body)
    } catch {
      res.writeHead(404)
      res.end('Not found')
    }
  })

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  const httpPort = server.address().port
  const bootStr = `${bootstrap[0].host}:${bootstrap[0].port}`

  console.log(
    JSON.stringify({
      httpPort,
      bootstrap: bootStr,
      aliceUrl: `http://127.0.0.1:${httpPort}/?bootstrap=${bootStr}&topic=pear-room-1&nick=Alice&autostart=1`,
      bobUrl: `http://127.0.0.1:${httpPort}/?bootstrap=${bootStr}&topic=pear-room-1&nick=Bob&autostart=1`
    })
  )
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
