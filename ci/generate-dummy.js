#!/usr/bin/env node
/**
 * generate-dummy.js
 *
 * Seeds _data/results.json with fake historical data for local Jekyll testing.
 * Does not require an adsbypasser checkout.
 *
 * Usage: node ci/generate-dummy.js
 */

import fs from "fs/promises";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DATA_FILE = path.resolve(__dirname, "../_data/results.json");

const DOMAINS = [
  "bc.vc",
  "bcvc.ink",
  "bit.ly",
  "clk.sh",
  "cpmlink.net",
  "droplink.co",
  "exe.io",
  "fc.lc",
  "gplinks.in",
  "linkvertise.com",
  "ouo.io",
  "shrinkme.io",
  "shorte.st",
  "up-load.io",
  "za.gl",
];

const STATUSES = ["passed", "unknown", "failed"];
const WEIGHTS = [0.70, 0.15, 0.15]; // 70% passed, 15% unknown, 15% failed

const REASON_MAP = {
  passed: ["VALID", "PROTOCOL_FLIP_LOOP"],
  unknown: ["PROTECTED", "JS_ONLY", "CLOUDFLARE_BOT_PROTECTION", "DDOS_GUARD_PROTECTION", "PLACEHOLDER"],
  failed: ["EXPIRED", "TIMEOUT"],
};

function weightedRandom() {
  const r = Math.random();
  let cumulative = 0;
  for (let i = 0; i < WEIGHTS.length; i++) {
    cumulative += WEIGHTS[i];
    if (r < cumulative) return STATUSES[i];
  }
  return STATUSES[STATUSES.length - 1];
}

function pickReason(status) {
  const reasons = REASON_MAP[status];
  return reasons[Math.floor(Math.random() * reasons.length)];
}

function weeksAgo(n) {
  const d = new Date();
  d.setDate(d.getDate() - n * 7);
  return d.toISOString().slice(0, 10);
}

const NUM_WEEKS = 8;

const dates = [];
for (let i = 0; i < NUM_WEEKS; i++) {
  dates.push(weeksAgo(i));
}

const runs = {};
for (const date of dates) {
  runs[date] = {};
  for (const domain of DOMAINS) {
    const status = weightedRandom();
    runs[date][domain] = { status, reason: pickReason(status) };
  }
}

const output = { dates, domains: [...DOMAINS].sort(), runs };

await fs.writeFile(DATA_FILE, JSON.stringify(output, null, 2) + "\n");
console.log(`Wrote dummy data to ${DATA_FILE}`);
console.log(`  ${dates.length} dates, ${DOMAINS.length} domains`);
