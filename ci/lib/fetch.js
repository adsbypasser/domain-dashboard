/**
 * HTTP fetch utilities for the domain checker.
 * Provides both native Node.js fetch and curl-impersonate fallback.
 */

import { execFile } from "child_process";
import { promisify } from "util";
import http from "http";
import https from "https";
import { URL } from "url";
import {
  REQUEST_TIMEOUT_MS,
  BROWSER_PROFILE,
  DEFAULT_HEADERS,
  CONTENT_PATTERNS,
  CLOUDFLARE_ERROR_DESCRIPTIONS,
} from "./check-config.js";

const execFileAsync = promisify(execFile);

/**
 * Unified function to handle SSL error detection and classification
 * @param {string} domain - The domain being checked (for logging)
 * @param {string} errorCode - The error code from the SSL error
 * @param {string} errorMessage - The error message from the SSL error
 * @param {Function} debugLog - Debug logging function
 * @returns {Object} Standardized error object with status and details
 */
function handleSSLError(domain, errorCode, errorMessage, debugLog) {
  debugLog(domain, "SSL certificate issue detected:", errorCode, errorMessage);
  return {
    status: "SSL_ISSUE",
    error: errorCode,
    message: errorMessage,
  };
}

/**
 * Fetch a URL with timeout and return status, headers, and body
 * This function handles the actual HTTP/HTTPS requests with proper error handling
 * @param {string} domain - The domain being checked (for logging)
 * @param {string} url - URL to fetch
 * @param {number} timeoutMs - Timeout in milliseconds
 * @param {Function} debugLog - Debug logging function
 * @returns {Promise<Object>} Response object with status, headers, and body
 */
export async function fetchUrl(domain, url, timeoutMs = REQUEST_TIMEOUT_MS, debugLog = () => {}) {
  debugLog(domain, "Fetching", url);

  // Extract domain from URL for error logging
  // This provides more detailed error information when debugging
  const urlObj = new URL(url);

  return new Promise((resolve) => {
    // Choose the appropriate HTTP client based on protocol
    // This ensures we use the correct client for HTTPS vs HTTP requests
    const client = urlObj.protocol === "https:" ? https : http;

    // Add default headers to the request
    // These headers help avoid bot detection by mimicking a real browser
    const requestOptions = {
      hostname: urlObj.hostname,
      port: urlObj.port,
      path: urlObj.pathname + urlObj.search,
      method: "GET",
      headers: DEFAULT_HEADERS,
    };

    // Implement request timeout to prevent hanging requests
    // This is crucial for handling slow or unresponsive servers
    const timer = setTimeout(() => {
      debugLog(domain, "Timeout fetching", url, "after", timeoutMs, "ms");
      resolve({ status: "TIMEOUT" });
    }, timeoutMs);

    // Make the actual HTTP request
    const req = client.request(requestOptions, (res) => {
      // Clear the timeout timer since we received a response
      clearTimeout(timer);

      // Log response headers for debugging purposes
      // This information is valuable for diagnosing issues
      debugLog(
        domain,
        "Response received for",
        url,
        "with status",
        res.statusCode,
      );
      debugLog(domain, "Response headers:");
      Object.entries(res.headers).forEach(function ([key, value]) {
        debugLog(domain, "  " + key + ": " + value);
      });

      // Collect response body data
      // We limit the body size to prevent memory issues with very large responses
      let body = "";
      res.on("data", (chunk) => {
        if (body.length < 8192) {
          body += chunk.toString();
        }
      });
      res.on("end", () => {
        debugLog(domain, "Response body size:", body.length, "bytes");
        resolve({ statusCode: res.statusCode, headers: res.headers, body });
      });
    });

    // Handle request errors
    // This includes network errors, DNS issues, and SSL/TLS problems
    req.on("error", (err) => {
      clearTimeout(timer);
      debugLog(domain, "Request error for", url, err.code, err.message);
      if (["ECONNREFUSED", "ENOTFOUND", "EHOSTUNREACH"].includes(err.code)) {
        resolve({ status: "REFUSED" });
      } else if (
        [
          "CERT_HAS_EXPIRED",
          "DEPTH_ZERO_SELF_SIGNED_CERT",
          "UNABLE_TO_VERIFY_LEAF_SIGNATURE",
        ].includes(err.code)
      ) {
        // Use unified SSL error handling
        const sslError = handleSSLError(domain, err.code, err.message, debugLog);
        resolve(sslError);
      } else {
        resolve({ status: "UNREACHABLE" });
      }
    });

    // Log when request is initiated
    debugLog(domain, "Initiating request to", url);

    req.end();
  });
}

/**
 * Fetch a URL using curl-impersonate to bypass TLS fingerprint-based bot detection.
 * curl-impersonate mimics the full TLS handshake of real browsers, defeating
 * Cloudflare and similar services that block non-browser TLS fingerprints.
 *
 * @param {string} domain - The domain being checked (for logging)
 * @param {string} url - URL to fetch
 * @param {number} timeoutMs - Timeout in milliseconds
 * @param {Function} debugLog - Debug logging function
 * @returns {Promise<Object|null>} Response object, low-level status object, or null if binary unavailable
 */
export async function fetchUrlWithCurlImpersonate(domain, url, timeoutMs = REQUEST_TIMEOUT_MS, debugLog = () => {}) {
  debugLog(domain, "Retrying with curl-impersonate:", url);
  const timeoutSec = Math.ceil(timeoutMs / 1000);

  try {
    const { stdout } = await execFileAsync(
      BROWSER_PROFILE.binary,
      ["-si", "-L", "--max-redirs", "5", "--max-time", String(timeoutSec), url],
      { maxBuffer: 2 * 1024 * 1024 },
    );

    // stdout contains one or more HTTP response blocks separated by \r\n\r\n
    // With -L, intermediate redirect responses appear before the final one.
    // Take the last two segments: final headers block + body.
    const parts = stdout.split("\r\n\r\n");
    if (parts.length < 2) {
      return { status: "UNREACHABLE" };
    }

    const rawHeaders = parts[parts.length - 2];
    const body = parts[parts.length - 1].substring(0, 8192);

    const lines = rawHeaders.split("\r\n");
    const statusMatch = lines[0].match(/^HTTP\/\S+\s+(\d+)/);
    if (!statusMatch) {
      return { status: "UNREACHABLE" };
    }
    const statusCode = parseInt(statusMatch[1], 10);

    const headers = {};
    for (const line of lines.slice(1)) {
      const colonIdx = line.indexOf(":");
      if (colonIdx > 0) {
        headers[line.substring(0, colonIdx).trim().toLowerCase()] =
          line.substring(colonIdx + 1).trim();
      }
    }

    debugLog(domain, "curl-impersonate response:", statusCode);
    return { statusCode, headers, body };
  } catch (err) {
    if (err.code === "ENOENT") {
      debugLog(domain, "curl-impersonate binary not found, skipping retry");
      return null;
    }
    debugLog(domain, "curl-impersonate error:", err.message);
    return { status: "UNREACHABLE" };
  }
}

/**
 * Classify a final (non-redirect) HTTP response into a domain status string.
 * Used to evaluate curl-impersonate retry results using the same rules as the
 * main check loop, without needing to re-enter the redirect-following logic.
 *
 * @param {string} domain - Domain being checked (for logging)
 * @param {Object} response - Response object from fetchUrlWithCurlImpersonate
 * @param {Function} debugLog - Debug logging function
 * @returns {string} Domain status string
 */
export function classifyFinalResponse(domain, { status, statusCode, headers = {}, body = "" }, debugLog = () => {}) {
  if (status) {
    return status;
  }

  if (statusCode >= 500) {
    const code = statusCode.toString();
    if (statusCode <= 526 && CLOUDFLARE_ERROR_DESCRIPTIONS[code]) {
      if (code === "525" || code === "526") {
        return handleSSLError(
          domain,
          `CLOUDFLARE_${code}`,
          CLOUDFLARE_ERROR_DESCRIPTIONS[code],
          debugLog,
        ).status;
      }
      return `CLOUDFLARE_${code}`;
    }
    return `SERVER_ERROR_${statusCode}`;
  }

  if (statusCode >= 400) {
    return `CLIENT_ERROR_${statusCode}`;
  }

  if (body) {
    if (
      body.includes("Cloudflare Ray ID") ||
      CONTENT_PATTERNS.WAF.some((p) => body.includes(p))
    ) {
      return "PROTECTED";
    }
    const emptyCheck = isEmptyOrJsOnly(domain, body);
    if (emptyCheck) return emptyCheck;
    if (CONTENT_PATTERNS.PLACEHOLDER.some((p) => body.includes(p))) {
      return "PLACEHOLDER";
    }
  }

  return "VALID";
}

/**
 * Determine if a page is blank or only contains JavaScript
 * This helps identify pages that don't provide meaningful content to users
 * @param {string} domain - The domain being checked (for logging)
 * @param {string} body - Response body to analyze
 * @returns {string|boolean} Status string or false if not empty/JS-only
 */
export function isEmptyOrJsOnly(domain, body) {
  // Handle empty response bodies
  if (!body) {
    return "EMPTY_PAGE";
  }

  // Remove head and noscript sections
  // These sections often contain metadata or fallback content that isn't relevant to content analysis
  let stripped = body.replace(/<head[^>]*>[\s\S]*?<\/head>/gi, "");
  stripped = stripped.replace(/<noscript[^>]*>[\s\S]*?<\/noscript>/gi, "");
  stripped = stripped.replace(/\s/g, "");

  // Extract script content
  // This helps distinguish between truly empty pages and pages that rely heavily on JavaScript
  const scriptMatches = body.match(/<script[^>]*>([\s\S]*?)<\/script>/gi);
  const scriptContent = scriptMatches
    ? scriptMatches
        .map((script) => script.replace(/<script[^>]*>|<\/script>/gi, ""))
        .join("")
        .trim()
    : "";

  // Classify pages based on content
  // JS_ONLY: Pages with no visible content but with JavaScript (may load content dynamically)
  // EMPTY_PAGE: Pages with no meaningful content at all
  if (stripped === "" && scriptContent) {
    return "JS_ONLY";
  }
  return stripped.length === 0 ? "EMPTY_PAGE" : false;
}
