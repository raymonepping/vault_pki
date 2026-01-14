import http from "node:http";
import crypto from "node:crypto";
import path from "node:path";
import { spawn } from "node:child_process";
import { promisify } from "node:util";
import { execFile } from "node:child_process";

import fs from "node:fs";
import fsp from "node:fs/promises";

const execFileAsync = promisify(execFile);

const PORT = Number(process.env.PORT || "3000");

// Current nginx leaf and chain used by the dashboard
const CERT_PATH = process.env.CERT_PATH || "/shared/certs/nginx.crt";
const CHAIN_PATH = process.env.CHAIN_PATH || "/shared/certs/nginx.chain.crt";
const CRL_PATH = process.env.CRL_PATH || "/shared/www/crl/pki-int.crl.pem";

// CAaS
const DEFAULT_OUT_BASE = process.env.DEFAULT_OUT_BASE || "/shared/www/issued";
const VAULT_ADDR = (process.env.VAULT_ADDR || "http://vault:8200").replace(/\/$/, "");
const VAULT_TOKEN = process.env.VAULT_TOKEN || "";

// Limits (keep it sane)
const MAX_COUNT = 50;
const MAX_JSON_BYTES = 64 * 1024; // 64 KB

function sendJson(res, code, obj) {
  res.writeHead(code, {
    "content-type": "application/json",
    "cache-control": "no-store",
  });
  res.end(JSON.stringify(obj, null, 2));
}

function sendText(res, code, text) {
  res.writeHead(code, {
    "content-type": "text/plain; charset=utf-8",
    "cache-control": "no-store",
  });
  res.end(text);
}

async function readBodyJson(req) {
  let size = 0;
  const chunks = [];
  for await (const c of req) {
    size += c.length;
    if (size > MAX_JSON_BYTES) throw new Error("request body too large");
    chunks.push(c);
  }
  const raw = Buffer.concat(chunks).toString("utf8").trim();
  if (!raw) return {};
  try {
    return JSON.parse(raw);
  } catch {
    throw new Error("invalid JSON body");
  }
}

function safe(v, fallback = null) {
  return v === undefined || v === null || v === "" ? fallback : v;
}

function normalizeSerialHex(s) {
  if (!s) return "";
  return String(s).replace(/[^0-9a-fA-F]/g, "").toUpperCase();
}

function isSafeRunId(run) {
  // 20260114-154735
  return typeof run === "string" && /^[0-9]{8}-[0-9]{6}$/.test(run);
}

function isSafeName(s) {
  // mount and role
  return typeof s === "string" && /^[a-zA-Z0-9][a-zA-Z0-9-_]{0,80}$/.test(s);
}

function isSafeTtl(s) {
  // keep it simple: "24h", "15m", "72h", "30s"
  return typeof s === "string" && /^[0-9]{1,6}[smhd]$/.test(s);
}

function countPemCertsFromText(pemText) {
  const m = pemText.match(/-----BEGIN CERTIFICATE-----/g);
  return m ? m.length : 0;
}

async function readCertMeta() {
  const pem = await fsp.readFile(CERT_PATH, "utf8");

  if (typeof crypto.X509Certificate !== "function") {
    throw new Error("crypto.X509Certificate is not available in this Node build");
  }

  const x509 = new crypto.X509Certificate(pem);
  const notBefore = new Date(x509.validFrom);
  const notAfter = new Date(x509.validTo);

  let chainExists = false;
  let chainBytes = null;
  let chainCertCount = null;

  if (CHAIN_PATH) {
    try {
      const st = await fsp.stat(CHAIN_PATH);
      chainExists = st.isFile();
      chainBytes = st.size;
      if (chainExists) {
        const chainText = await fsp.readFile(CHAIN_PATH, "utf8");
        chainCertCount = countPemCertsFromText(chainText);
      }
    } catch {
      chainExists = false;
    }
  }

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

    chainPath: CHAIN_PATH,
    chainFile: CHAIN_PATH ? path.basename(CHAIN_PATH) : null,
    chainExists,
    chainCertCount,
    chainBytes,
  };
}

function tsFolderUtc() {
  const d = new Date();
  const pad = (n) => String(n).padStart(2, "0");
  return `${d.getUTCFullYear()}${pad(d.getUTCMonth() + 1)}${pad(d.getUTCDate())}-${pad(
    d.getUTCHours()
  )}${pad(d.getUTCMinutes())}${pad(d.getUTCSeconds())}`;
}

function applyCnTemplate(tpl, i) {
  const n = Number(i);

  // supports: "app-%03d.lab.local"
  const m = tpl.match(/%0(\d+)d/);
  if (m) {
    const width = Number(m[1]);
    const padded = String(n).padStart(width, "0");
    return tpl.replace(/%0\d+d/, padded);
  }

  if (tpl.includes("%d")) return tpl.replace("%d", String(n));
  if (tpl.includes("{i}")) return tpl.replaceAll("{i}", String(n));

  return `${tpl}${n}`;
}

function writeFileAtomic(p, content, mode) {
  const tmp = `${p}.tmp`;
  fs.writeFileSync(tmp, content, { encoding: "utf8" });
  if (mode) fs.chmodSync(tmp, mode);
  fs.renameSync(tmp, p);
}

function certMetaFromPem(pem) {
  const x509 = new crypto.X509Certificate(pem);
  return {
    subject: x509.subject,
    issuer: x509.issuer,
    notAfter: x509.validTo,
    fingerprint256: x509.fingerprint256,
    serialNumber: x509.serialNumber,
  };
}

async function existsDir(p) {
  try {
    const st = await fsp.stat(p);
    return st.isDirectory();
  } catch {
    return false;
  }
}

async function vaultIssue({ mount, role, common_name, alt_names, ip_sans, ttl }) {
  if (!VAULT_TOKEN) throw new Error("VAULT_TOKEN is not set for certinfo");

  const url = `${VAULT_ADDR}/v1/${mount}/issue/${role}`;
  const payload = { common_name, ttl };
  if (alt_names) payload.alt_names = alt_names;
  if (ip_sans) payload.ip_sans = ip_sans;

  const r = await fetch(url, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-vault-token": VAULT_TOKEN,
    },
    body: JSON.stringify(payload),
  });

  if (!r.ok) {
    const t = await r.text().catch(() => "");
    throw new Error(`Vault issue failed (${r.status}): ${t}`);
  }
  return r.json();
}

function listRuns(baseDir, limit = 20) {
  if (!fs.existsSync(baseDir)) return [];

  const entries = fs
    .readdirSync(baseDir, { withFileTypes: true })
    .filter((d) => d.isDirectory())
    .map((d) => d.name)
    .sort()
    .reverse()
    .slice(0, limit);

  return entries.map((name) => {
    const summaryPath = path.join(baseDir, name, "summary.json");
    let summary = null;
    try {
      summary = fs.existsSync(summaryPath) ? JSON.parse(fs.readFileSync(summaryPath, "utf8")) : null;
    } catch {
      summary = null;
    }
    return {
      folder: name,
      url: `/issued/${name}/`,
      summaryUrl: `/issued/${name}/summary.json`,
      count: summary?.count ?? null,
      createdAt: summary?.createdAt ?? null,
    };
  });
}

/**
 * CRL parsing
 * We cache based on CRL file mtime to avoid re-running openssl every call.
 */
let opensslAvailable = null; // null = unknown
let crlCache = {
  mtimeMs: null,
  parsed: null,
};

async function ensureOpenSSL() {
  if (opensslAvailable !== null) return opensslAvailable;
  try {
    const { stdout } = await execFileAsync("openssl", ["version"], { encoding: "utf8" });
    opensslAvailable = stdout.toLowerCase().includes("openssl");
    return opensslAvailable;
  } catch {
    opensslAvailable = false;
    return false;
  }
}

async function parseCrlWithOpenSSL(crlPath) {
  if (!(await ensureOpenSSL())) {
    return { ok: false, error: "openssl not found in container. Install it (apk add --no-cache openssl zip)." };
  }

  let st;
  try {
    st = await fsp.stat(crlPath);
  } catch {
    return { ok: false, error: `CRL file not found at ${crlPath}` };
  }

  // cached?
  if (crlCache.parsed && crlCache.mtimeMs === st.mtimeMs) {
    return crlCache.parsed;
  }

  let text = "";
  try {
    const r = await execFileAsync("openssl", ["crl", "-in", crlPath, "-noout", "-text"], { encoding: "utf8" });
    text = r.stdout || "";
  } catch (e) {
    return { ok: false, error: `failed to run openssl crl on ${crlPath}: ${String(e?.message || e)}` };
  }

  const lastUpdate = (text.match(/Last Update:\s*(.+)\n/i) || [])[1] || null;
  const nextUpdate = (text.match(/Next Update:\s*(.+)\n/i) || [])[1] || null;

  const serialMatches = [...text.matchAll(/Serial Number:\s*([0-9A-Fa-f]+)/g)];
  const revokedSerials = serialMatches.map((m) => normalizeSerialHex(m[1])).filter(Boolean);

  const parsed = {
    ok: true,
    crlPath,
    crlFile: path.basename(crlPath),
    lastUpdate,
    nextUpdate,
    revokedCount: revokedSerials.length,
    revokedSerials,
  };

  crlCache = { mtimeMs: st.mtimeMs, parsed };
  return parsed;
}

/**
 * ZIP bundling: stream /shared/www/issued/<run>/summary.json + cert-* folders.
 */
async function streamRunZip(res, runFolder) {
  const runDir = path.join(DEFAULT_OUT_BASE, runFolder);
  if (!(await existsDir(runDir))) {
    sendJson(res, 404, { ok: false, error: `Run not found: ${runFolder}` });
    return;
  }

  // Pre-check summary.json exists
  const summaryPath = path.join(runDir, "summary.json");
  try {
    const st = await fsp.stat(summaryPath);
    if (!st.isFile()) throw new Error("summary.json missing");
  } catch {
    sendJson(res, 404, { ok: false, error: `Run missing summary.json: ${runFolder}` });
    return;
  }

  res.writeHead(200, {
    "content-type": "application/zip",
    "cache-control": "no-store",
    "content-disposition": `attachment; filename="caas-${runFolder}.zip"`,
  });

  // zip -qr - summary.json cert-*
  const proc = spawn("sh", ["-lc", "zip -qr - summary.json cert-*"], { cwd: runDir });

  proc.stdout.pipe(res);

  let stderr = "";
  proc.stderr.on("data", (d) => {
    stderr += d.toString("utf8");
  });

  proc.on("close", (code) => {
    if (code === 0) return;
    // If streaming already started, just end. Client will see a failed download.
    try {
      if (!res.headersSent) {
        sendJson(res, 500, { ok: false, error: "zip failed", detail: stderr.trim() });
      } else {
        res.end();
      }
    } catch {
      res.end();
    }
  });
}

const server = http.createServer(async (req, res) => {
  // basic hardening for a lab service
  res.setHeader("x-content-type-options", "nosniff");

  try {
    const url = new URL(req.url, `http://${req.headers.host}`);

    if (url.pathname === "/healthz") {
      return sendJson(res, 200, {
        ok: true,
        vaultTokenSet: Boolean(VAULT_TOKEN),
        outBase: DEFAULT_OUT_BASE,
      });
    }

    if (url.pathname === "/cert" && req.method === "GET") {
      try {
        const meta = await readCertMeta();
        return sendJson(res, 200, meta);
      } catch (e) {
        return sendJson(res, 500, { ok: false, error: String(e?.message || e) });
      }
    }

    if (url.pathname === "/crl-meta" && req.method === "GET") {
      const parsed = await parseCrlWithOpenSSL(CRL_PATH);
      if (!parsed.ok) return sendJson(res, 500, parsed);

      const qSerial = normalizeSerialHex(url.searchParams.get("serial"));
      const serialRevoked = qSerial ? parsed.revokedSerials.includes(qSerial) : null;

      const { revokedSerials, ...base } = parsed;
      return sendJson(res, 200, { ...base, serialQuery: qSerial || null, serialRevoked });
    }

    // ----- CAaS Portal API -----

    // GET /caas/list?limit=20
    if (url.pathname === "/caas/list" && req.method === "GET") {
      const limitRaw = Number(url.searchParams.get("limit") || "20");
      const limit = Math.max(1, Math.min(100, Number.isFinite(limitRaw) ? limitRaw : 20));
      const runs = listRuns(DEFAULT_OUT_BASE, limit);
      return sendJson(res, 200, { ok: true, baseDir: DEFAULT_OUT_BASE, runs });
    }

    // GET /caas/bundle?run=20260114-154735
    if (url.pathname === "/caas/bundle" && req.method === "GET") {
      const run = String(url.searchParams.get("run") || "").trim();
      if (!isSafeRunId(run)) {
        return sendJson(res, 400, { ok: false, error: "Invalid run. Expected: YYYYMMDD-HHMMSS" });
      }
      return streamRunZip(res, run);
    }

    // POST /caas/issue
    if (url.pathname === "/caas/issue" && req.method === "POST") {
      const body = await readBodyJson(req);

      const mount = safe(body.mount, "pki-int");
      const role = safe(body.role, "nginx");
      const ttl = safe(body.ttl, "24h");
      const countRaw = Number(safe(body.count, 1));

      const cnTemplate = safe(body.cn_template, "service-%03d.lab.local");
      const altNames = safe(body.alt_names, "localhost");
      const ipSans = safe(body.ip_sans, "127.0.0.1");

      if (!isSafeName(mount) || !isSafeName(role)) {
        return sendJson(res, 400, { ok: false, error: "Invalid mount or role" });
      }
      if (!isSafeTtl(ttl)) {
        return sendJson(res, 400, { ok: false, error: "Invalid ttl. Example: 24h, 15m, 72h" });
      }

      const count = Math.max(1, Math.min(MAX_COUNT, Number.isFinite(countRaw) ? countRaw : 1));

      const runFolder = tsFolderUtc();
      const outDir = path.join(DEFAULT_OUT_BASE, runFolder);
      await fsp.mkdir(outDir, { recursive: true });

      const issued = [];

      for (let i = 1; i <= count; i++) {
        const cn = applyCnTemplate(cnTemplate, i);

        const issuedJson = await vaultIssue({
          mount,
          role,
          common_name: cn,
          alt_names: altNames,
          ip_sans: ipSans,
          ttl,
        });

        const d = issuedJson?.data || {};
        const leaf = String(d.certificate || "");
        const key = String(d.private_key || "");
        const issuing = String(d.issuing_ca || "");

        if (!leaf || !key) throw new Error("Vault response missing certificate/private_key");

        const certN = String(i).padStart(3, "0");
        const itemDir = path.join(outDir, `cert-${certN}`);
        await fsp.mkdir(itemDir, { recursive: true });

        const leafPath = path.join(itemDir, "leaf.crt");
        const keyPath = path.join(itemDir, "leaf.key");
        const issuingPath = path.join(itemDir, "issuing_ca.crt");
        const chainPath = path.join(itemDir, "chain.crt");

        // Keep it simple: leaf + issuing CA
        writeFileAtomic(leafPath, leaf, 0o644);
        writeFileAtomic(keyPath, key, 0o600);
        writeFileAtomic(issuingPath, issuing || "", 0o644);
        writeFileAtomic(chainPath, `${leaf}\n${issuing}\n`, 0o644);

        const meta = certMetaFromPem(leaf);

        issued.push({
          index: i,
          commonName: cn,
          notAfter: meta.notAfter,
          serial: meta.serialNumber,
          fingerprint256: meta.fingerprint256,
          urls: {
            folder: `/issued/${runFolder}/cert-${certN}/`,
            leaf: `/issued/${runFolder}/cert-${certN}/leaf.crt`,
            key: `/issued/${runFolder}/cert-${certN}/leaf.key`,
            chain: `/issued/${runFolder}/cert-${certN}/chain.crt`,
          },
        });
      }

      const summary = {
        ok: true,
        createdAt: new Date().toISOString(),
        mount,
        role,
        ttl,
        count,
        cnTemplate,
        altNames,
        ipSans,
        outDir,
        runFolder,
        summaryUrl: `/issued/${runFolder}/summary.json`,
        bundleUrl: `/caas/bundle?run=${runFolder}`,
        items: issued,
      };

      writeFileAtomic(path.join(outDir, "summary.json"), JSON.stringify(summary, null, 2), 0o644);

      const latest = {
        ok: true,
        latest: runFolder,
        summaryUrl: summary.summaryUrl,
        bundleUrl: summary.bundleUrl,
        count,
        createdAt: summary.createdAt,
      };
      writeFileAtomic(path.join(DEFAULT_OUT_BASE, "latest.json"), JSON.stringify(latest, null, 2), 0o644);

      return sendJson(res, 200, summary);
    }

    // Helpful method mismatch
    if (url.pathname.startsWith("/caas/") || url.pathname === "/cert" || url.pathname === "/crl-meta") {
      return sendJson(res, 405, { ok: false, error: "method not allowed" });
    }

    return sendJson(res, 404, { ok: false, error: "not found" });
  } catch (e) {
    return sendJson(res, 500, { ok: false, error: String(e?.message || e) });
  }
});

server.keepAliveTimeout = 65_000;
server.headersTimeout = 70_000;

server.listen(PORT, () => {
  console.log(`certinfo listening on :${PORT}`);
  console.log(`CERT_PATH=${CERT_PATH}`);
  console.log(`CHAIN_PATH=${CHAIN_PATH}`);
  console.log(`CRL_PATH=${CRL_PATH}`);
  console.log(`DEFAULT_OUT_BASE=${DEFAULT_OUT_BASE}`);
  console.log(`VAULT_ADDR=${VAULT_ADDR}`);
  console.log(`VAULT_TOKEN set: ${Boolean(VAULT_TOKEN)}`);
});
