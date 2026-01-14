import fs from "node:fs";
import http from "node:http";
import crypto from "node:crypto";
import path from "node:path";

const PORT = process.env.PORT || 3000;
const CERT_PATH = process.env.CERT_PATH || "/shared/certs/nginx.crt";
const CHAIN_PATH = process.env.CHAIN_PATH || "/shared/certs/nginx.chain.crt";

function countPemCertBlocks(pemText) {
  const matches = pemText.match(/-----BEGIN CERTIFICATE-----/g);
  return matches ? matches.length : 0;
}

function readChainMeta() {
  try {
    const pem = fs.readFileSync(CHAIN_PATH, "utf8");
    return {
      chainPath: CHAIN_PATH,
      chainFile: path.basename(CHAIN_PATH),
      chainExists: true,
      chainCertCount: countPemCertBlocks(pem),
      chainBytes: Buffer.byteLength(pem, "utf8"),
    };
  } catch (err) {
    return {
      chainPath: CHAIN_PATH,
      chainFile: path.basename(CHAIN_PATH),
      chainExists: false,
      chainCertCount: 0,
      chainBytes: 0,
      chainError: String(err),
    };
  }
}

function readLeafMeta() {
  const pem = fs.readFileSync(CERT_PATH, "utf8");

  if (typeof crypto.X509Certificate !== "function") {
    throw new Error(
      "crypto.X509Certificate is not available in this Node build",
    );
  }

  const x509 = new crypto.X509Certificate(pem);
  const notBefore = new Date(x509.validFrom);
  const notAfter = new Date(x509.validTo);

  return {
    certPath: CERT_PATH,
    certFile: path.basename(CERT_PATH),
    subject: x509.subject,
    issuer: x509.issuer,
    validFrom: notBefore.toISOString(),
    validTo: notAfter.toISOString(),
    validToEpochMs: notAfter.getTime(),
    nowEpochMs: Date.now(),
    fingerprint256: x509.fingerprint256,
    serialNumber: x509.serialNumber,
  };
}

function readCertMeta() {
  return {
    ...readLeafMeta(),
    ...readChainMeta(),
  };
}

const server = http.createServer((req, res) => {
  if (req.url === "/healthz") {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ ok: true }));
    return;
  }

  if (req.url === "/cert") {
    try {
      const meta = readCertMeta();
      res.writeHead(200, {
        "content-type": "application/json",
        "cache-control": "no-store",
      });
      res.end(JSON.stringify(meta, null, 2));
    } catch (err) {
      res.writeHead(500, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: false, error: String(err) }));
    }
    return;
  }

  res.writeHead(404, { "content-type": "application/json" });
  res.end(JSON.stringify({ ok: false, error: "not found" }));
});

server.listen(PORT, () => {
  console.log(
    `certinfo listening on :${PORT}, leaf=${CERT_PATH}, chain=${CHAIN_PATH}`,
  );
});
