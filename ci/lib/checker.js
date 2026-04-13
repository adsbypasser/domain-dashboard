/**
 * Domain check orchestration.
 * Combines DNS resolution, HTTP fetching, and status classification.
 */

import dns from "dns/promises";
import { URL } from "url";
import { MAX_REDIRECTS, CLOUDFLARE_ERROR_DESCRIPTIONS, CONTENT_PATTERNS } from "./check-config.js";
import {
  fetchUrl,
  fetchUrlWithCurlImpersonate,
  classifyFinalResponse,
  isEmptyOrJsOnly,
} from "./fetch.js";

/**
 * Create a debug logging function bound to the given debug settings.
 * Call this once in main() after parsing CLI flags, then pass the result
 * into checkDomain().
 *
 * @param {boolean} globalDebug - Log debug output for all domains
 * @param {string|null} specificDomain - Log debug output only for this domain
 * @returns {Function} debugLog(domain, ...args)
 */
export function makeDebugLog(globalDebug, specificDomain) {
  return function debugLog(domain, ...args) {
    if (globalDebug) {
      console.log("[DEBUG]", ...args);
      return;
    }
    if (specificDomain && domain === specificDomain) {
      console.log("[DEBUG]", ...args);
    }
  };
}

/**
 * Check if a domain is resolvable via DNS (IPv4/IPv6)
 * @param {string} domain - Domain to check
 * @param {Function} debugLog - Debug logging function
 * @returns {Promise<boolean>} True if domain is resolvable
 */
async function isDomainResolvable(domain, debugLog) {
  try {
    await dns.resolve4(domain);
    debugLog(domain, domain, "DNS resolved via A record");
    return true;
  } catch {
    try {
      await dns.resolve6(domain);
      debugLog(domain, domain, "DNS resolved via AAAA record");
      return true;
    } catch {
      debugLog(domain, domain, "DNS NOT resolved");
      return false;
    }
  }
}

/**
 * Sequential domain check for one domain
 * Tests both HTTPS and HTTP protocols with comprehensive error detection
 * @param {string} domain - Domain to check
 * @param {Function} debugLog - Debug logging function
 * @returns {Promise<string>} Status result
 */
async function checkDomainStatus(domain, debugLog) {
  const protocols = ["https", "http"];

  for (const protocol of protocols) {
    let url = `${protocol}://${domain}`;
    const visited = new Set();
    let redirects = 0;

    while (redirects < MAX_REDIRECTS) {
      // Track visited URLs to detect redirect loops
      // This is essential to prevent infinite loops in redirect chains
      if (visited.has(url)) {
        debugLog(domain, domain, "Redirect loop detected at", url);
        return "REDIRECT_LOOP";
      }
      visited.add(url);

      const { status, statusCode, headers, body, error, message } =
        await fetchUrl(domain, url, undefined, debugLog);

      if (status) {
        debugLog(domain, domain, "Low-level status:", status);
        // Special handling for SSL errors
        if (status === "SSL_ISSUE") {
          debugLog(domain, domain, "SSL issue:", error, message);
          // Try HTTP instead of HTTPS for sites with SSL issues
          // This provides a fallback for sites with certificate problems
          if (protocol === "https") {
            debugLog(domain, domain, "Will try HTTP instead of HTTPS");
            break; // Exit the while loop to try HTTP
          }
          return status;
        }
        return status;
      }

      // Follow redirects
      // Handle HTTP 3xx redirect responses by following the Location header
      if (statusCode >= 300 && statusCode < 400 && headers.location) {
        try {
          const redirectUrl = new URL(headers.location, url);

          // Special handling for protocol flips (HTTP ↔ HTTPS)
          // Some sites legitimately flip between protocols for the same domain
          // This is common for sites that want to ensure users are on the correct protocol
          if (
            redirectUrl.hostname === domain &&
            ((url.startsWith("https://") && redirectUrl.protocol === "http:") ||
              (url.startsWith("http://") && redirectUrl.protocol === "https:"))
          ) {
            // Check if we've already visited this protocol for this domain
            // This detects infinite protocol flip loops while allowing legitimate single flips
            const protocolKey = `${redirectUrl.protocol}//${redirectUrl.hostname}${redirectUrl.pathname}${redirectUrl.search}`;
            if (visited.has(protocolKey)) {
              debugLog(
                domain,
                domain,
                "Protocol flip redirect loop detected:",
                url,
                "->",
                redirectUrl.toString(),
              );
              // This is a special case - the site works but has a protocol flip loop
              // Let's try to determine if the site is actually accessible
              // Protocol flip loops are often accessible in browsers due to client-side handling
              return "PROTOCOL_FLIP_LOOP";
            }
          }

          url = redirectUrl.toString();
          redirects++;
          debugLog(domain, domain, "Redirect to", url);
          continue;
        } catch {
          debugLog(
            domain,
            domain,
            "Error parsing redirect URL:",
            headers.location,
          );
          return "INVALID_REDIRECT";
        }
      }

      // HTTP errors (5xx server errors)
      // These can indicate server-side issues or Cloudflare protection
      if (statusCode >= 500) {
        debugLog(domain, domain, "Server error", statusCode);
        // Check for Cloudflare-specific errors and add descriptions
        // Cloudflare uses specific error codes to indicate different types of issues
        if (statusCode >= 500 && statusCode <= 526) {
          const errorCode = statusCode.toString();
          if (CLOUDFLARE_ERROR_DESCRIPTIONS[errorCode]) {
            debugLog(
              domain,
              domain,
              `Cloudflare Error ${errorCode}:`,
              CLOUDFLARE_ERROR_DESCRIPTIONS[errorCode],
            );
            // Handle Cloudflare SSL errors (525 and 526) as SSL issues
            // These specifically indicate SSL/TLS handshake or certificate problems
            // Classifying them as SSL_ISSUE ensures consistent handling with other SSL errors
            if (errorCode === "525" || errorCode === "526") {
              debugLog(domain, "SSL certificate issue detected:", `CLOUDFLARE_${errorCode}`, CLOUDFLARE_ERROR_DESCRIPTIONS[errorCode]);
              return "SSL_ISSUE";
            }
            // Handle other Cloudflare errors as CLOUDFLARE_ codes
            return `CLOUDFLARE_${errorCode}`;
          }
        }
        return `SERVER_ERROR_${statusCode}`;
      }

      // Client errors (4xx errors)
      // These often indicate access restrictions or bot detection
      if (statusCode >= 400) {
        debugLog(domain, domain, "Client error", statusCode);
        // Add more specific handling for 403 errors
        // 403 Forbidden often indicates bot detection or access restrictions
        if (statusCode === 403) {
          debugLog(
            domain,
            domain,
            "403 Forbidden - Possible bot detection or access restriction",
          );
          // Check if it's a Cloudflare protection
          // Cloudflare uses specific headers to indicate bot protection
          const isCloudflare =
            headers["server"] && headers["server"].includes("cloudflare");
          const isCloudflareMitigated = headers["cf-mitigated"] === "challenge";

          if (isCloudflare || isCloudflareMitigated) {
            debugLog(
              domain,
              domain,
              "403 appears to be from Cloudflare bot detection",
            );
            const curlResult = await fetchUrlWithCurlImpersonate(domain, url, undefined, debugLog);
            if (curlResult !== null) {
              return classifyFinalResponse(domain, curlResult, debugLog);
            }
            return "CLOUDFLARE_BOT_PROTECTION";
          }

          // Check for DDoS-Guard protection
          // Another common bot protection service that returns 403 errors
          const isDDoSGuard =
            headers["server"] && headers["server"].includes("ddos-guard");
          if (isDDoSGuard) {
            debugLog(
              domain,
              domain,
              "403 appears to be from DDoS-Guard protection",
            );
            const curlResult = await fetchUrlWithCurlImpersonate(domain, url, undefined, debugLog);
            if (curlResult !== null) {
              return classifyFinalResponse(domain, curlResult, debugLog);
            }
            return "DDOS_GUARD_PROTECTION";
          }
        }
        return `CLIENT_ERROR_${statusCode}`;
      }

      // Inspect response body for additional error information
      // Some servers include error details in the response body rather than headers
      if (body) {
        // Cloudflare 5xx detection in response body
        // Cloudflare sometimes embeds error information directly in the HTML response
        for (const code of [
          "500",
          "502",
          "503",
          "504",
          "520",
          "521",
          "522",
          "523",
          "524",
          "525",
          "526",
        ]) {
          // Look for Cloudflare error messages in the response body
          if (body.includes(`Error ${code}`)) {
            debugLog(domain, domain, "Cloudflare error detected:", code);
            // Handle Cloudflare SSL errors (525 and 526) as SSL issues
            // Consistent handling with HTTP status code-based SSL error detection
            if (code === "525" || code === "526") {
              debugLog(domain, "SSL certificate issue detected:", `CLOUDFLARE_${code}`, CLOUDFLARE_ERROR_DESCRIPTIONS[code]);
              return "SSL_ISSUE";
            }
            // Handle other Cloudflare errors as CLOUDFLARE_ codes
            return `CLOUDFLARE_${code}`;
          }
        }

        // WAF / protection detection
        // Detect Web Application Firewall protection pages
        // These indicate the site is protected and may not be accessible to automated tools
        if (
          body.includes("Cloudflare Ray ID") ||
          CONTENT_PATTERNS.WAF.some((p) => body.includes(p))
        ) {
          debugLog(domain, domain, "Protected by WAF");
          return "PROTECTED";
        }

        // Placeholder / blank / JS-only detection
        const emptyCheck = isEmptyOrJsOnly(domain, body);
        if (emptyCheck) {
          debugLog(domain, domain, "Empty/JS-only page detected:", emptyCheck);
          return emptyCheck;
        }

        // Check for placeholder/parked pages
        // These indicate domains that are not actively hosting content
        if (CONTENT_PATTERNS.PLACEHOLDER.some((p) => body.includes(p))) {
          debugLog(domain, domain, "Placeholder page detected");
          return "PLACEHOLDER";
        }
      }

      return "VALID";
    }

    // If we've reached the max redirects, check if it's a protocol flip situation
    // This handles cases where legitimate redirect chains exceed our limit
    if (redirects >= MAX_REDIRECTS) {
      // Check if the last few redirects were protocol flips
      debugLog(
        domain,
        domain,
        "Max redirects reached, checking for protocol flip pattern",
      );
      return "REDIRECT_LOOP";
    }
  }

  return "UNREACHABLE";
}

/**
 * Wrapper function that combines DNS resolution with domain status checking
 * @param {string} domain - Domain to check
 * @param {Function} debugLog - Debug logging function
 * @returns {Promise<Object>} Result object with domain, status, and metadata
 */
export async function checkDomain(domain, debugLog = () => {}) {
  const resolvable = await isDomainResolvable(domain, debugLog);
  if (!resolvable) {
    return { domain, status: "EXPIRED", resolvable: false, accessible: false };
  }

  const status = await checkDomainStatus(domain, debugLog);
  // Define which statuses are considered accessible
  const accessibleStatuses = ["VALID", "PROTOCOL_FLIP_LOOP"];
  return {
    domain,
    status,
    resolvable: true,
    accessible: accessibleStatuses.includes(status),
  };
}

/**
 * Run async tasks with bounded concurrency, preserving result order.
 * @param {Array<() => Promise<any>>} tasks - Array of zero-argument async functions
 * @param {number} concurrency - Maximum number of tasks running in parallel
 * @returns {Promise<any[]>} Results in the same order as tasks
 */
export async function pooledMap(tasks, concurrency) {
  const results = new Array(tasks.length);
  let next = 0;
  async function worker() {
    while (next < tasks.length) {
      const index = next++;
      results[index] = await tasks[index]();
    }
  }
  await Promise.all(
    Array.from({ length: Math.min(concurrency, tasks.length) }, worker),
  );
  return results;
}
