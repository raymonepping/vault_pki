import fs from "node:fs";
import http from "node:http";
import crypto from "node:crypto";
import { execFileSync, spawnSync } from "node:child_process";

const PORT = process.env.PORT || 3000;

const CERT_PATH = process.env.CERT_PATH || "/shared/certs/nginx.crt";
const CHAIN_PATH = process.env.CHAIN_PATH || "/shared/certs/nginx.chain.crt";
const CRL_PATH = process.env.CRL_PATH || "/shared/www/crl/pki-int.crl.pem";

function hasOpenSSL() {
  const r = spawnSync("openssl", ["version"], { encoding: "utf8" });
  return r.status === 0;
}

function countPemCerts(path) {
  if (!fs.existsSync(path)) return 0;
  const s = fs.readFileSync(path, "utf8");
  const m = s.match(/-----BEGIN CERTIFICATE-----/g);
  return m ? m.length : 0;
}

function readCertMeta() {
  const pem = fs.readFileSync(CERT_PATH, "utf8");

  if (typeof crypto.X509Certificate !== "function") {
    throw new Error("crypto.X509Certificate is not available in this Node build");
  }

  const x509 = new crypto.X509Certificate(pem);
  const notBefore = new Date(x509.validFrom);
  const notAfter = new Date(x509.validTo);

  return {
    certPath: CERT_PATH,
    certFile: CERT_PATH.split("/").pop(),
    subject: x509.subject,
    issuer: x509.issuer,
    validFrom: notBefore.toISOString(),
    validTo: notAfter.toISOString(),
    validToEpochMs: notAfter.getTime(),
    nowEpochMs: Date.now(),
    fingerprint256: x509.fingerprint256,
    serialNumber: x509.serialNumber,

    chainPath: CHAIN_PATH,
    chainFile: CHAIN_PATH ? CHAIN_PATH.split("/").pop() : null,
    chainExists: CHAIN_PATH ? fs.existsSync(CHAIN_PATH) : false,
    chainCertCount: CHAIN_PATH ? countPemCerts(CHAIN_PATH) : null,
    chainBytes: CHAIN_PATH && fs.existsSync(CHAIN_PATH) ? fs.statSync(CHAIN_PATH).size : null,
  };
}

function normalizeSerialHex(s) {
  if (!s) return "";
  return String(s).replace(/[^0-9a-fA-F]/g, "").toUpperCase();
}

function parseCrlWithOpenSSL(crlPath) {
  if (!fs.existsSync(crlPath)) {
    return { ok: false, error: `CRL file not found at ${crlPath}` };
  }

  let text = "";
  try {
    text = execFileSync("openssl", ["crl", "-in", crlPath, "-noout", "-text"], {
      encoding: "utf8",
    });
  } catch (e) {
    return {
      ok: false,
      error: `failed to run openssl crl on ${crlPath}: ${String(e)}`,
    };
  }

  const lastUpdate = (text.match(/Last Update:\s*(.+)\n/i) || [])[1] || null;
  const nextUpdate = (text.match(/Next Update:\s*(.+)\n/i) || [])[1] || null;

  const serialMatches = [...text.matchAll(/Serial Number:\s*([0-9A-Fa-f]+)/g)];
  const revokedSerials = serialMatches.map((m) => normalizeSerialHex(m[1])).filter(Boolean);

  return {
    ok: true,
    crlPath,
    crlFile: crlPath.split("/").pop(),
    lastUpdate,
    nextUpdate,
    revokedCount: revokedSerials.length,
    revokedSerials, // internal use only
  };
}

function sendJson(res, code, obj) {
  res.writeHead(code, {
    "content-type": "application/json",
    "cache-control": "no-store",
  });
  res.end(JSON.stringify(obj, null, 2));
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);

  if (url.pathname === "/healthz") {
    return sendJson(res, 200, { ok: true });
  }

  if (url.pathname === "/cert") {
    try {
      return sendJson(res, 200, readCertMeta());
    } catch (err) {
      return sendJson(res, 500, { ok: false, error: String(err) });
    }
  }

  if (url.pathname === "/crl-meta") {
    if (!hasOpenSSL()) {
      return sendJson(res, 500, {
        ok: false,
        error: "openssl not found in container. Install it (apk add --no-cache openssl).",
      });
    }

    const parsed = parseCrlWithOpenSSL(CRL_PATH);
    if (!parsed.ok) return sendJson(res, 500, parsed);

    const qSerial = normalizeSerialHex(url.searchParams.get("serial"));
    const serialRevoked = qSerial ? parsed.revokedSerials.includes(qSerial) : null;

    const { revokedSerials, ...base } = parsed;

    return sendJson(res, 200, {
      ...base,
      serialQuery: qSerial || null,
      serialRevoked,
    });
  }

  return sendJson(res, 404, { ok: false, error: "not found" });
});

server.listen(PORT, () => {
  console.log(`certinfo listening on :${PORT}`);
  console.log(`CERT_PATH=${CERT_PATH}`);
  console.log(`CHAIN_PATH=${CHAIN_PATH}`);
  console.log(`CRL_PATH=${CRL_PATH}`);
});
