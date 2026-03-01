const https = require("https");
const http = require("http");
const fs = require("fs");
const path = require("path");

const certDir = path.join(__dirname, "certs");
const options = {
  key: fs.readFileSync(path.join(certDir, "server.key")),
  cert: fs.readFileSync(path.join(certDir, "server.crt")),
};

const HTTPS_PORT = 2223;
const HTTP_PORT = 2222;

https
  .createServer(options, (req, res) => {
    const proxy = http.request(
      {
        hostname: "localhost",
        port: HTTP_PORT,
        path: req.url,
        method: req.method,
        headers: req.headers,
      },
      (proxyRes) => {
        res.writeHead(proxyRes.statusCode, proxyRes.headers);
        proxyRes.pipe(res, { end: true });
      }
    );
    proxy.on("error", (err) => {
      res.writeHead(502);
      res.end("Bad Gateway");
    });
    req.pipe(proxy, { end: true });
  })
  .listen(HTTPS_PORT, "0.0.0.0", () => {
    console.log(`HTTPS proxy listening on https://0.0.0.0:${HTTPS_PORT} -> http://localhost:${HTTP_PORT}`);
  });
