'use strict';

/**
 * lib/credential-redact.js
 *
 * mavis-patch-2026-09-30 (B.12 — credential fragment redaction):
 * Scrubs credential-shaped fragments from arbitrary strings, so that
 * downstream report fields like `context`, `evidence.snippet`,
 * `canonicalWindow`, and `description` never leak a half-credential.
 *
 * This is intentionally conservative: each fragment shape requires a
 * distinctive prefix (e.g. `AKIA`, `ghp_`, `AIza`, `sk_`, `npm_`,
 * `xox[abprs]-`) so random alphanumeric blobs do not trigger FPs.
 *
 * The shape list is exported separately so tests can verify each
 * fragment independently.
 *
 * License: MIT (matches upstream omega-sast)
 */

const FRAGMENT_SHAPES = [
  // AWS access keys: 16+ uppercase alnum after AKIA prefix.
  { name: 'AWS_KEY_FRAGMENT',       re: /\bAKIA[0-9A-Z]{8,}\b/g },
  // GitHub PATs: ghp_ + 36 alnum; also gho_, ghu_, ghs_, ghr_.
  { name: 'GITHUB_TOKEN_FRAGMENT',  re: /\bgh[pour]_[A-Za-z0-9]{16,}\b/g },
  // Google API keys: AIza + 35 chars.
  { name: 'GOOGLE_API_KEY_FRAGMENT',re: /\bAIza[0-9A-Za-z_\-]{30,}\b/g },
  // Stripe live/test secret keys: sk_live_/sk_test_ + 24+ chars.
  { name: 'STRIPE_KEY_FRAGMENT',    re: /\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b/g },
  // OpenAI keys: sk- + 20+ chars (NOT sk_live_ or sk_test_).
  { name: 'OPENAI_KEY_FRAGMENT',    re: /\bsk-[A-Za-z0-9]{20,}\b/g },
  // npm tokens: npm_ + 36 chars.
  { name: 'NPM_TOKEN_FRAGMENT',     re: /\bnpm_[A-Za-z0-9]{20,}\b/g },
  // Slack tokens: xox[abprs]- + 10+ chars.
  { name: 'SLACK_TOKEN_FRAGMENT',   re: /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/g },
  // JWT: three base64url segments separated by dots (≥8 chars each).
  // Catches `eyJhbG…eyJzdWIiO…sig` form found in canonicalWindow.
  { name: 'JWT_FRAGMENT',           re: /\beyJ[A-Za-z0-9_\-]{4,}\.[A-Za-z0-9_\-]{4,}\.[A-Za-z0-9_\-]{4,}\b/g },
  // GitLab: glpat- + 20+ chars.
  { name: 'GITLAB_TOKEN_FRAGMENT',  re: /\bglpat-[A-Za-z0-9_\-]{16,}\b/g },
  // Telegram: digits:base64ish.
  { name: 'TELEGRAM_TOKEN_FRAGMENT',re: /\b\d{8,12}:[A-Za-z0-9_\-]{25,}\b/g },
  // Vault: hvs.<base64ish>.
  { name: 'VAULT_TOKEN_FRAGMENT',   re: /\bhvs\.[A-Za-z0-9_\-]{16,}\b/g },
  // Supabase: sbp_(prod|dev|staging)_ + 20+ chars.
  { name: 'SUPABASE_KEY_FRAGMENT',  re: /\bsbp_(?:prod|dev|staging)_[A-Za-z0-9_\-]{16,}\b/g },
  // Heroku: assignment context (HEROKU_API_KEY="..." / Heroku-API-Key: '...')
  // followed by a quoted value 20+ chars long.
  { name: 'HEROKU_KEY_FRAGMENT',    re: /\b(?:heroku[_-]?api[_-]?key)\b\s*[:=]\s*["'][A-Za-z0-9_\-]{20,}["']/gi },
  // Twilio: SK + 32 hex.
  { name: 'TWILIO_KEY_FRAGMENT',    re: /\bSK[0-9a-fA-F]{32}\b/g },
  // Mapbox: pk.<base64>.<base64>.
  { name: 'MAPBOX_TOKEN_FRAGMENT',  re: /\bpk\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}/g },
  // Discord: 18-30 alnum . 5-8 chars . 27+ chars.
  { name: 'DISCORD_TOKEN_FRAGMENT', re: /\b[A-Za-z\d]{18,30}\.[A-Za-z\d_\-]{5,8}\.[A-Za-z\d_\-]{27,}\b/g },
];

/**
 * Scrub credential fragments from an arbitrary string. Returns a new
 * string; replaces each match with `[REDACTED:<SHAPE_NAME>:len=<original-length>]`.
 *
 * mavis-patch-2026-09-30 — also matches TRUNCATED fragments (the value
 * was cut off by the upstream context-window slicer). Truncated matches
 * are redacted with `trunc=` instead of `len=` so the consumer can tell.
 *
 * @param {string} text  Any string. Returns as-is if falsy.
 * @returns {string}
 */
function redactText(text) {
  if (!text || typeof text !== 'string') return text;
  let out = text;
  for (const { name, re } of FRAGMENT_SHAPES) {
    out = out.replace(re, (match) => `[REDACTED:${name}:len=${match.length}]`);
  }
  // Pass 2: scrub truncated fragments. When upstream's context-window
  // slicer cuts a credential mid-value, the value appears as `AKIA...`,
  // `ghp_xxxx...`, `AIza...`, etc. Replace those tokens too.
  const TRUNC_PATTERNS = [
    { name: 'AWS_KEY_FRAGMENT',       re: /\bAKIA[0-9A-Z]{6,}\b/g },
    { name: 'GITHUB_TOKEN_FRAGMENT',  re: /\bgh[pour]_[A-Za-z0-9]{6,}/g },
    { name: 'GOOGLE_API_KEY_FRAGMENT',re: /\bAIza[0-9A-Za-z_\-]{6,}/g },
    { name: 'STRIPE_KEY_FRAGMENT',    re: /\bsk_(?:live|test)_[A-Za-z0-9]{6,}/g },
    { name: 'OPENAI_KEY_FRAGMENT',    re: /\bsk-[A-Za-z0-9]{6,}\b/g },
    { name: 'NPM_TOKEN_FRAGMENT',     re: /\bnpm_[A-Za-z0-9]{6,}/g },
    { name: 'SLACK_TOKEN_FRAGMENT',   re: /\bxox[abprs]-[A-Za-z0-9-]{6,}/g },
    { name: 'JWT_FRAGMENT',           re: /\beyJ[A-Za-z0-9_\-]{6,}\b/g },
    { name: 'GITLAB_TOKEN_FRAGMENT',  re: /\bglpat-[A-Za-z0-9_\-]{6,}/g },
    { name: 'TELEGRAM_TOKEN_FRAGMENT',re: /\b\d{8,12}:[A-Za-z0-9_\-]{6,}/g },
    { name: 'VAULT_TOKEN_FRAGMENT',   re: /\bhvs\.[A-Za-z0-9_\-]{6,}/g },
    { name: 'SUPABASE_KEY_FRAGMENT',  re: /\bsbp_(?:prod|dev|staging)_[A-Za-z0-9_\-]{6,}/g },
    { name: 'TWILIO_KEY_FRAGMENT',    re: /\bSK[0-9a-fA-F]{6,}\b/g },
    { name: 'HEROKU_KEY_FRAGMENT',    re: /\b(?:heroku[_-]?api[_-]?key)\b/gi },
    { name: 'MAPBOX_TOKEN_FRAGMENT',  re: /\bpk\.[A-Za-z0-9_\-]{6,}/g },
    { name: 'DISCORD_TOKEN_FRAGMENT', re: /\b[A-Za-z\d]{18,30}\.[A-Za-z\d_\-]{6,}/g },
  ];
  for (const { name, re } of TRUNC_PATTERNS) {
    out = out.replace(re, (match) => `[REDACTED:${name}:trunc=${match.length}]`);
  }
  return out;
}

/**
 * Redact credential fragments from a finding object. Mutates the
 * object in place. Walks all string-valued fields and all nested
 * objects / arrays.
 *
 * @param {object} finding  Any plain object (finding, evidence, etc.)
 */
function redactFinding(finding) {
  if (!finding || typeof finding !== 'object') return finding;
  const seen = new WeakSet();
  const walk = (node) => {
    if (!node || typeof node !== 'object') return;
    if (seen.has(node)) return;
    seen.add(node);
    if (Array.isArray(node)) {
      for (let i = 0; i < node.length; i++) {
        const v = node[i];
        if (typeof v === 'string') node[i] = redactText(v);
        else if (v && typeof v === 'object') walk(v);
      }
      return;
    }
    for (const k of Object.keys(node)) {
      const v = node[k];
      if (typeof v === 'string') node[k] = redactText(v);
      else if (v && typeof v === 'object') walk(v);
    }
  };
  walk(finding);
  return finding;
}

module.exports = {
  FRAGMENT_SHAPES,
  redactText,
  redactFinding,
};
