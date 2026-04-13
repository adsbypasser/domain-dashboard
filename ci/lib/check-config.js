/**
 * Configuration constants for the domain checker
 */

/**
 * Maximum number of redirects to follow before considering it a loop
 */
export const MAX_REDIRECTS = 5;

/**
 * Request timeout in milliseconds
 * Set to 60s to accommodate slow-loading websites
 */
export const REQUEST_TIMEOUT_MS = 60000;

/**
 * Pool of browser profiles for curl-impersonate.
 * Each entry pairs the binary name with its matching User-Agent so the TLS
 * fingerprint and UA are always consistent. One profile is chosen randomly at
 * startup and reused for the entire run.
 */
export const BROWSER_PROFILES = [
  {
    binary: "curl_chrome116",
    userAgent:
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36",
  },
  {
    binary: "curl_chrome110",
    userAgent:
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36",
  },
  {
    binary: "curl_ff117",
    userAgent:
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:117.0) Gecko/20100101 Firefox/117.0",
  },
];

export const BROWSER_PROFILE =
  BROWSER_PROFILES[Math.floor(Math.random() * BROWSER_PROFILES.length)];

/**
 * Browser-like headers to avoid bot detection.
 * The User-Agent is aligned with the selected BROWSER_PROFILE so that
 * primary fetch requests and curl-impersonate retries present the same identity.
 * Includes Referer header to appear more like legitimate traffic.
 */
export const DEFAULT_HEADERS = {
  "User-Agent": BROWSER_PROFILE.userAgent,
  Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
  "Accept-Language": "en-US,en;q=0.5",
  "Accept-Encoding": "gzip, deflate, br, zstd",
  Connection: "keep-alive",
  "Upgrade-Insecure-Requests": "1",
  "Sec-Fetch-Dest": "document",
  "Sec-Fetch-Mode": "navigate",
  "Sec-Fetch-Site": "cross-site",
  "Sec-GPC": "1",
  DNT: "1",
  TE: "trailers",
  Referer: "https://www.google.com/",
};

/**
 * Content detection patterns organized by category
 * These patterns help identify different types of pages and protection mechanisms
 */
export const CONTENT_PATTERNS = {
  /**
   * Text patterns indicating placeholder or parked pages
   * These indicate domains that are not actively hosting content
   * Common examples include default web server pages or domain parking services
   */
  PLACEHOLDER: [
    "Welcome to nginx!",
    "This domain is parked",
    "Buy this domain",
    "Domain for sale",
    "Default PLESK Page",
  ],

  /**
   * Text patterns indicating Web Application Firewall protection
   * These indicate the site is protected by security services and may not
   * be accessible to automated tools without proper handling
   */
  WAF: [
    "Attention Required! | Cloudflare",
    "Checking your browser before accessing",
    "DDOS protection by",
  ],
};

/**
 * Cloudflare error descriptions for better understanding of issues
 * Only includes error codes that are actually handled in the code
 */
export const CLOUDFLARE_ERROR_DESCRIPTIONS = {
  500: "Internal Server Error - Cloudflare could not retrieve the web page",
  502: "Bad Gateway - Cloudflare could not contact the origin server",
  503: "Service Temporarily Unavailable - The server is temporarily unable to handle the request",
  504: "Gateway Timeout - Cloudflare timed out contacting the origin server",
  520: "Web Server Returns an Unknown Error - The origin server returned an empty, unknown, or unexplained response",
  521: "Web Server Is Down - The origin server refused the connection",
  522: "Connection Timed Out - Cloudflare could not negotiate a TCP handshake with the origin server",
  523: "Origin Is Unreachable - Cloudflare could not reach the origin server",
  524: "A Timeout Occurred - Cloudflare was able to complete a TCP connection but timed out waiting for an HTTP response",
  525: "SSL Handshake Failed - Cloudflare could not negotiate an SSL/TLS handshake with the origin server",
  526: "Invalid SSL Certificate - Cloudflare could not validate the SSL certificate of the origin server",
};

/**
 * Status icons for visual representation of domain check results
 */
export const STATUS_ICONS = {
  VALID: "✅",
  PLACEHOLDER: "⚠️",
  EMPTY_PAGE: "📄",
  JS_ONLY: "📜",
  CLIENT_ERROR: "🚫",
  SERVER_ERROR: "🔥",
  SSL_ISSUE: "🔒",
  EXPIRED: "❌",
  UNREACHABLE: "🌐",
  REFUSED: "⛔",
  TIMEOUT: "⏱️",
  REDIRECT_LOOP: "🔁",
  PROTOCOL_FLIP_LOOP: "🔄",
  INVALID_REDIRECT: "🔀",
  PROTECTED: "🛡️",
  CLOUDFLARE_BOT_PROTECTION: "🛡️403",
  DDOS_GUARD_PROTECTION: "🛡️403",
  CLOUDFLARE_500: "☁️500",
  CLOUDFLARE_502: "☁️502",
  CLOUDFLARE_503: "☁️503",
  CLOUDFLARE_504: "☁️504",
  CLOUDFLARE_520: "☁️520",
  CLOUDFLARE_521: "☁️521",
  CLOUDFLARE_522: "☁️522",
  CLOUDFLARE_523: "☁️523",
  CLOUDFLARE_524: "☁️524",
  CLOUDFLARE_525: "☁️525",
  CLOUDFLARE_526: "☁️526",
};
