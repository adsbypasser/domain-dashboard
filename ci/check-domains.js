#!/usr/bin/env node

/**
 * CI Domain Checker
 *
 * This script checks the accessibility of domains extracted from JSDoc comments
 * in the adsbypasser project. It performs comprehensive checks including DNS
 * resolution, HTTP/HTTPS accessibility, SSL validation, and detection of
 * various error conditions.
 *
 * Features:
 *  - DNS resolution (IPv4/IPv6)
 *  - HTTP/HTTPS accessibility testing
 *  - SSL/TLS certificate validation
 *  - Redirect loop detection
 *  - Timeout handling for slow responses
 *  - Placeholder/parked page detection
 *  - Cloudflare/WAF/5xx error detection
 *  - Blank or JavaScript-only page detection
 *  - Parallel domain checking with configurable concurrency (default: 5)
 *  - Staggered starts within each wave to spread DNS queries
 *  - Referer header to appear more like legitimate traffic
 *
 * Set ADSBYPASSER_PATH env var to point at an adsbypasser checkout.
 * Use --output <file> to write structured JSON results to a file.
 */

import { extractDomainsFromJSDoc } from "./lib/jsdoc.js";
import fs from "fs/promises";
import { STATUS_ICONS, CLOUDFLARE_ERROR_DESCRIPTIONS } from "./lib/check-config.js";
import { checkDomain, makeDebugLog, pooledMap } from "./lib/checker.js";

/**
 * Main function that orchestrates the domain checking process
 * Extracts domains from JSDoc comments and checks each one
 * This function handles command-line arguments and controls the overall flow
 */
async function main() {
  const args = process.argv.slice(2);

  // Parse command-line arguments
  // This allows users to control the script's behavior
  let categories = null;
  let specificDomain = null;

  // Check if --verbose is in the arguments
  // This enables detailed debugging output
  const verboseIndex = args.indexOf("--verbose");
  let globalDebug = false;
  if (verboseIndex !== -1) {
    globalDebug = true;

    // Check if there's a domain specified after --verbose
    // This allows debugging of specific domains only
    if (args[verboseIndex + 1] && !args[verboseIndex + 1].startsWith("-")) {
      specificDomain = args[verboseIndex + 1];
      globalDebug = false;

      // Remove --verbose and the domain from args
      args.splice(verboseIndex, 2);
    } else {
      // Just remove --verbose from args
      args.splice(verboseIndex, 1);
    }
  }

  // Parse --output <path> flag
  const outputIndex = args.indexOf("--output");
  let outputPath = null;
  if (outputIndex !== -1) {
    outputPath = args[outputIndex + 1];
    args.splice(outputIndex, 2);
  }

  // Parse --concurrency <n> flag (default: 5)
  const concurrencyIndex = args.indexOf("--concurrency");
  let concurrencyLimit = 5;
  if (concurrencyIndex !== -1) {
    const parsed = parseInt(args[concurrencyIndex + 1], 10);
    if (!Number.isFinite(parsed) || parsed < 1) {
      console.error("--concurrency must be a positive integer");
      process.exit(1);
    }
    concurrencyLimit = parsed;
    args.splice(concurrencyIndex, 2);
  }

  // Check for --help flag
  if (args.includes("--help") || args.includes("-h")) {
    console.log("Usage: node ci/check-domains.js [options] [categories...]");
    console.log("");
    console.log("Options:");
    console.log("  --verbose          Enable verbose output");
    console.log("  --output <file>    Write results as JSON to <file>");
    console.log("  --concurrency <n>  Max parallel domain checks (default: 5)");
    console.log("  --help, -h         Show this help message");
    console.log("");
    console.log("Environment:");
    console.log("  ADSBYPASSER_PATH   Path to adsbypasser checkout");
    console.log("");
    console.log("Categories:");
    console.log("  file, image, link  Check only specific site categories");
    console.log("");
    console.log("Examples:");
    console.log(
      "  ADSBYPASSER_PATH=../adsbypasser node ci/check-domains.js --output /tmp/results.json",
    );
    console.log(
      "  node ci/check-domains.js file link  Check only file and link domains",
    );
    process.exit(0);
  }

  // Remaining args are categories
  categories = args.length ? args : null;

  const debugLog = makeDebugLog(globalDebug, specificDomain);

  if (globalDebug) {
    console.log("Verbose mode enabled");
  } else if (specificDomain) {
    console.log(`Debug output limited to domain: ${specificDomain}`);
  }

  console.log("Extracting domains from sites directory...");
  console.log(`Categories: ${categories ? categories.join(", ") : "all"}`);

  if (specificDomain) {
    console.log(`Checking specific domain only: ${specificDomain}`);
  }

  try {
    let domains;
    if (specificDomain) {
      // If a specific domain is provided, only check that domain
      // This is useful for debugging individual domains
      domains = [specificDomain];
    } else {
      // Otherwise, extract domains from JSDoc as usual
      // This processes all domains found in the codebase
      domains = await extractDomainsFromJSDoc(categories);
    }

    const uniqueDomains = domains;

    console.log(`Found ${uniqueDomains.length} domains`);
    if (!uniqueDomains.length) {
      return console.log("No domains found.");
    }

    // In non-verbose mode, show the "Checking:" header
    // This provides a clean list of domains being processed
    if (!globalDebug) {
      console.log("Checking:");
    }

    const results = await pooledMap(
      uniqueDomains.map((domain, domainIndex) => async () => {
        // Stagger starts within the first wave to spread DNS queries
        const staggerMs = (domainIndex % concurrencyLimit) * 100;
        await new Promise((r) => setTimeout(r, staggerMs));

        if (globalDebug) {
          console.log(`\nChecking ${domain}...`);
        }

        try {
          const result = await checkDomain(domain, debugLog);
          const icon = STATUS_ICONS[result.status] || "❓";

          if (!globalDebug) {
            // Print domain and result atomically on one line to avoid interleaving
            console.log(`- ${domain} ${icon}`);
          } else {
            if (result.status.startsWith("CLOUDFLARE_")) {
              const errorCode = result.status.split("_")[1];
              if (CLOUDFLARE_ERROR_DESCRIPTIONS[errorCode]) {
                console.log(
                  `${icon} ${result.status} - ${CLOUDFLARE_ERROR_DESCRIPTIONS[errorCode]}`,
                );
              } else {
                console.log(`${icon} ${result.status}`);
              }
            } else if (result.status === "SSL_ISSUE") {
              if (result.error && result.message) {
                console.log(
                  `${icon} ${result.status} - ${result.error}: ${result.message}`,
                );
              } else {
                console.log(`${icon} ${result.status}`);
              }
            } else if (result.status === "PROTOCOL_FLIP_LOOP") {
              console.log(
                `${icon} ${result.status} - Site has HTTP/HTTPS protocol flip but is likely accessible`,
              );
            } else if (result.status === "DDOS_GUARD_PROTECTION") {
              console.log(
                `${icon} ${result.status} - Site is protected by DDoS-Guard and may be accessible in browsers`,
              );
            } else {
              console.log(`${icon} ${result.status}`);
            }
          }

          return result;
        } catch (error) {
          if (globalDebug) {
            console.error(`Error checking domain ${domain}:`, error.message);
            console.log(`❌ CHECK_FAILED`);
          } else {
            console.log(`- ${domain} ❌`);
          }
          return { domain, status: "CHECK_FAILED" };
        }
      }),
      concurrencyLimit,
    );

    // Write JSON output file if --output was specified
    if (outputPath) {
      await fs.writeFile(outputPath, JSON.stringify(results, null, 2));
      console.log(`Results written to ${outputPath}`);
    }

    // Only show summary and problematic domains when NOT in specific domain debug mode
    // This keeps output clean when debugging individual domains
    if (!specificDomain) {
      // Add blank line after checking section in non-verbose mode
      if (!globalDebug) {
        console.log(""); // Empty line after domain list
      }

      // Summary
      console.log("--------------------------------------------------");
      console.log("SUMMARY:");

      const counts = results.reduce((acc, r) => {
        acc[r.status] = (acc[r.status] || 0) + 1;
        return acc;
      }, {});

      // Show VALID count
      const validCount = counts["VALID"] || 0;
      console.log(`✅ VALID: ${validCount}`);

      // Show Problem count (all non-VALID domains)
      const NON_PROBLEM_STATUSES = ["VALID", "PROTOCOL_FLIP_LOOP"];
      const problemCount = results.filter(
        (r) => !NON_PROBLEM_STATUSES.includes(r.status),
      ).length;
      console.log(`⚠️ Problem: ${problemCount}`);

      // Show Total count
      console.log(`📊 Total: ${results.length}`);
      console.log(""); // Ensure blank line after summary counts

      // Show detailed problematic domains grouped by status
      const problematic = results.filter(
        (r) => !NON_PROBLEM_STATUSES.includes(r.status),
      );
      if (problematic.length > 0) {
        console.log("PROBLEMATIC DOMAIN(S):");

        // Group domains by status
        const groupedProblems = {};
        problematic.forEach((r) => {
          if (!groupedProblems[r.status]) {
            groupedProblems[r.status] = [];
          }
          groupedProblems[r.status].push(r.domain);
        });

        // Display grouped problems
        Object.keys(groupedProblems).forEach((status, index) => {
          // Add extra spacing before each group except the first
          if (index > 0) {
            console.log(""); // Extra blank line between groups
          }

          const domains = groupedProblems[status];
          let statusLine = `${STATUS_ICONS[status] || "❓"} ${status}`;

          // Add Cloudflare error descriptions if applicable
          if (status.startsWith("CLOUDFLARE_")) {
            const errorCode = status.split("_")[1];
            // Check if we have a description for this Cloudflare error code
            if (CLOUDFLARE_ERROR_DESCRIPTIONS[errorCode]) {
              statusLine += ` - ${CLOUDFLARE_ERROR_DESCRIPTIONS[errorCode]}`;
            }
          } else if (status === "SSL_ISSUE") {
            // For SSL issues, add a general description
            statusLine += " - SSL/TLS certificate or handshake issues";
          } else if (status === "PROTOCOL_FLIP_LOOP") {
            statusLine +=
              " - Sites with HTTP/HTTPS protocol flip but likely accessible";
          }

          console.log(statusLine);

          // List domains with indentation
          domains.forEach((domain) => {
            console.log(`- ${domain}`);
          });
        });

        console.log(""); // Extra blank line at the end
      }
    }
  } catch (error) {
    console.error("Error during domain checking:", error);
    process.exit(1);
  }
}

// Execute the main function and handle any uncaught errors
main().catch((error) => {
  console.error("Unhandled error:", error);
  process.exit(1);
});
