#!/usr/bin/env node
/**
 * update-results.js
 *
 * Merges a single check-domains run (JSON file) into _data/results.json.
 *
 * Usage: node ci/update-results.js <results-json-path>
 *
 * The results JSON is the array written by check-domains.js --output,
 * with shape: [{ domain, status, resolvable, accessible }, ...]
 */

import fs from "fs/promises";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DATA_FILE = path.resolve(__dirname, "../_data/results.json");
const MAX_DATES = 52;

/**
 * Map a raw check-domains status string to passed/unknown/failed.
 * @param {string} status
 * @returns {"passed"|"unknown"|"failed"}
 */
function mapStatus(status) {
  if (!status) return "failed";
  if (status === "VALID" || status === "PROTOCOL_FLIP_LOOP") return "passed";
  if (status === "EXPIRED" || status === "TIMEOUT") return "failed";
  return "unknown";
}

async function main() {
  const inputPath = process.argv[2];
  if (!inputPath) {
    console.error("Usage: node ci/update-results.js <results-json-path>");
    process.exit(1);
  }

  // Read the new run results
  const raw = JSON.parse(await fs.readFile(inputPath, "utf-8"));

  // Read existing aggregated results (or start fresh)
  let existing;
  try {
    existing = JSON.parse(await fs.readFile(DATA_FILE, "utf-8"));
  } catch {
    existing = { dates: [], domains: [], runs: {} };
  }

  // Today's date as YYYY-MM-DD
  const today = new Date().toISOString().slice(0, 10);

  // Build the run entry for today
  const runEntry = {};
  for (const { domain, status } of raw) {
    runEntry[domain] = { status: mapStatus(status), reason: status ?? null };
  }

  // Merge domains (union, sorted)
  const domainSet = new Set([...existing.domains, ...Object.keys(runEntry)]);
  const domains = Array.from(domainSet).sort();

  // Prepend today's date (skip if it already exists to avoid duplicates)
  let dates = existing.dates.filter((d) => d !== today);
  dates = [today, ...dates];

  // Update runs map
  const runs = { ...existing.runs, [today]: runEntry };

  // Prune beyond MAX_DATES
  if (dates.length > MAX_DATES) {
    const removed = dates.splice(MAX_DATES);
    for (const d of removed) {
      delete runs[d];
    }
  }

  const output = { dates, domains, runs };
  await fs.writeFile(DATA_FILE, JSON.stringify(output, null, 2) + "\n");
  console.log(`Updated ${DATA_FILE} — ${dates.length} dates, ${domains.length} domains`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
