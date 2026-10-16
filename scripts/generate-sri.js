#!/usr/bin/env node
/**
 * generate-sri.js
 *
 * Security fix: Subresource Integrity (SRI) for first-party scripts.
 *
 * What it does:
 *  1. Computes sha384 SRI hashes for every local <script src="..."> tag in
 *     index.html and rewrites the `integrity` attribute (adding one if
 *     missing). Run as part of the build so hashes always match the served
 *     bytes — this removes the "stale hash breaks production" footgun.
 *  2. Verifies openpgp.min.js against a pinned sha384 hash. The worker loads
 *     it via importScripts(), which does not support SRI attributes, so the
 *     pin is checked at build time instead: if the library's content changed
 *     without the pin being updated on purpose, the build FAILS. That is what
 *     protects users from a tampered/compromised crypto library being
 *     silently served.
 *
 * Usage:  node scripts/generate-sri.js [--check]
 *   --check : do not write files; exit non-zero if anything is out of date
 *             or the pinned hash mismatch occurs (for CI).
 */

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const ROOT = path.resolve(__dirname, "..");
const INDEX_HTML = path.join(ROOT, "index.html");
const OPENPGP_FILE = path.join(ROOT, "openpgp.min.js");

// Pinned sha384 hash of openpgp.min.js (OpenPGP.js v6.3.1 minified bundle).
// Update deliberately only when upgrading the library on purpose.
const PINNED_OPENPGP_SHA384 =
  "sha384-sPmo7pGITv1/X4Bq5p4najbJZGUD3noWlHwrihDBwJ87a7DTu7sSr6uj+B5t/KA+";

const CHECK_ONLY = process.argv.includes("--check");

function sriHash(filePath) {
  const data = fs.readFileSync(filePath);
  const digest = crypto.createHash("sha384").update(data).digest("base64");
  return `sha384-${digest}`;
}

function fail(msg) {
  console.error(`[sri] ERROR: ${msg}`);
  process.exitCode = 1;
  return true;
}

// ---- 1. Pin check for the worker-loaded crypto library -------------------
function verifyOpenpgpPin() {
  const actual = sriHash(OPENPGP_FILE);
  if (actual !== PINNED_OPENPGP_SHA384) {
    return fail(
      "openpgp.min.js integrity mismatch!\n" +
        `  expected: ${PINNED_OPENPGP_SHA384}\n` +
        `  actual:   ${actual}\n` +
        "If you upgraded OpenPGP.js on purpose, update PINNED_OPENPGP_SHA384 in scripts/generate-sri.js."
    );
  }
  console.log("[sri] openpgp.min.js matches pinned hash.");
  return false;
}

// ---- 2. Inject/refresh SRI on local <script src> tags in index.html ------
function rewriteIndexHtml() {
  let html = fs.readFileSync(INDEX_HTML, "utf8");
  let changed = false;
  let errored = false;

  html = html.replace(
    /<script\b([^>]*?)\bsrc="([^"]+)"([^>]*?)>/gi,
    (match, pre, src, post) => {
      // Only handle local scripts (no protocol-relative or remote URLs).
      if (/^(https?:)?\/\//i.test(src) || /^data:/i.test(src)) return match;

      const filePath = path.join(ROOT, src.split("?")[0].split("#")[0]);
      if (!fs.existsSync(filePath)) {
        errored = fail(`script src "${src}" referenced in index.html not found`);
        return match;
      }
      const hash = sriHash(filePath);

      // Strip any existing integrity/crossorigin so we can re-add canonically.
      // Preserve `defer`/`async` (they live after src in the original tag).
      const defer = /\bdefer\b/i.test(post) ? " defer" : "";
      const async_ = /\basync\b/i.test(post) ? " async" : "";
      const attrs = `${pre}src="${src}"${post}`
        .replace(/\s*integrity="[^"]*"/gi, "")
        .replace(/\s*crossorigin="[^"]*"/gi, "")
        .replace(/\s*defer\b/gi, "")
        .replace(/\s*async\b/gi, "");

      const rebuilt = `<script${attrs} integrity="${hash}" crossorigin="anonymous"${defer}${async_}>`;
      if (rebuilt !== match) {
        changed = true;
        console.log(`[sri] ${src}: integrity set to ${hash.slice(0, 27)}…`);
      }
      return rebuilt;
    }
  );

  if (changed && !CHECK_ONLY) {
    fs.writeFileSync(INDEX_HTML, html);
    console.log("[sri] index.html updated.");
  } else if (changed && CHECK_ONLY) {
    return fail("index.html SRI attributes are out of date (run: npm run build)");
  }
  return errored;
}

// ---- main -----------------------------------------------------------------
let hadError = false;
hadError = verifyOpenpgpPin() || hadError;
hadError = rewriteIndexHtml() || hadError;

if (!hadError) {
  console.log(CHECK_ONLY ? "[sri] check passed." : "[sri] done.");
} else {
  console.error("[sri] failed — see errors above.");
  process.exit(1);
}
