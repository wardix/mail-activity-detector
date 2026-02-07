import { join } from "path";
import { readFileSync, existsSync } from "fs";

const WEBHOOKS_PATH = process.env.WEBHOOKS_PATH || join(import.meta.dir, "../../webhooks.json");
const EXCEPTIONS_PATH = process.env.EXCEPTIONS_PATH || join(import.meta.dir, "../../exceptions.json");

// ============================================
// Webhook configuration from JSON file
// ============================================

export interface WebhookConfig {
  name: string;
  url: string;
  method: string;
  headers: Record<string, string> | null;
  bodyTemplate: Record<string, unknown> | string | null;
  alertTypes?: ("unusual_location" | "brute_force")[];
  enabled: boolean;
}

/**
 * Load webhook configurations from JSON file
 */
export function getEnabledWebhooks(): WebhookConfig[] {
  try {
    if (!existsSync(WEBHOOKS_PATH)) {
      console.warn(`Webhooks config not found: ${WEBHOOKS_PATH}`);
      return [];
    }

    const content = readFileSync(WEBHOOKS_PATH, "utf-8");
    const webhooks = JSON.parse(content) as WebhookConfig[];

    return webhooks.filter(w => w.enabled);
  } catch (error) {
    console.error("Failed to load webhooks config:", error);
    return [];
  }
}

// ============================================
// Exceptions configuration from JSON file
// ============================================

export interface AccountException {
  username: string;
  countryCode: string;
  note?: string;
}

export interface IpWhitelistEntry {
  ip: string;
  note?: string;
}

interface ExceptionsConfig {
  accountExceptions?: AccountException[];
  ipWhitelist?: IpWhitelistEntry[];
}

let exceptionsCache: ExceptionsConfig | null = null;
let exceptionsCacheTime = 0;
const CACHE_TTL_MS = 60 * 1000; // Reload every 1 minute

/**
 * Load exceptions from JSON file (with caching)
 * Supports both old format (array) and new format (object with accountExceptions and ipWhitelist)
 */
function loadExceptions(): ExceptionsConfig {
  const now = Date.now();

  // Return cached if still valid
  if (exceptionsCache && now - exceptionsCacheTime < CACHE_TTL_MS) {
    return exceptionsCache;
  }

  try {
    if (!existsSync(EXCEPTIONS_PATH)) {
      console.warn(`Exceptions config not found: ${EXCEPTIONS_PATH}`);
      exceptionsCache = { accountExceptions: [], ipWhitelist: [] };
      exceptionsCacheTime = now;
      return exceptionsCache;
    }

    const content = readFileSync(EXCEPTIONS_PATH, "utf-8");
    const parsed = JSON.parse(content);

    // Support old format (array of account exceptions)
    if (Array.isArray(parsed)) {
      exceptionsCache = { accountExceptions: parsed, ipWhitelist: [] };
    } else {
      exceptionsCache = parsed as ExceptionsConfig;
    }

    exceptionsCacheTime = now;
    return exceptionsCache;
  } catch (error) {
    console.error("Failed to load exceptions config:", error);
    return { accountExceptions: [], ipWhitelist: [] };
  }
}

/**
 * Check if an account has exception for a country
 */
export function checkAccountException(username: string, countryCode: string): boolean {
  const config = loadExceptions();
  const exceptions = config.accountExceptions || [];
  return exceptions.some(
    e => e.username === username && e.countryCode === countryCode
  );
}

/**
 * Check if an IP is whitelisted from brute force detection
 */
export function isIpWhitelisted(ip: string): boolean {
  const config = loadExceptions();
  const whitelist = config.ipWhitelist || [];

  return whitelist.some(entry => {
    // Exact match
    if (entry.ip === ip) return true;

    // CIDR notation support (simple /8, /16, /24)
    if (entry.ip.includes("/")) {
      return matchCidr(ip, entry.ip);
    }

    return false;
  });
}

/**
 * CIDR matching for IPv4 and IPv6
 */
function matchCidr(ip: string, cidr: string): boolean {
  const [network, prefixStr] = cidr.split("/");
  const prefix = parseInt(prefixStr, 10);

  // Detect IP version
  const isIpv6 = ip.includes(":");
  const isNetworkIpv6 = network.includes(":");

  // Must be same IP version
  if (isIpv6 !== isNetworkIpv6) return false;

  if (isIpv6) {
    return matchCidrV6(ip, network, prefix);
  } else {
    return matchCidrV4(ip, network, prefix);
  }
}

/**
 * IPv4 CIDR matching
 */
function matchCidrV4(ip: string, network: string, prefix: number): boolean {
  const ipParts = ip.split(".").map(Number);
  const networkParts = network.split(".").map(Number);

  if (ipParts.length !== 4 || networkParts.length !== 4) return false;

  // Convert to 32-bit integers
  const ipInt = ((ipParts[0] << 24) | (ipParts[1] << 16) | (ipParts[2] << 8) | ipParts[3]) >>> 0;
  const networkInt = ((networkParts[0] << 24) | (networkParts[1] << 16) | (networkParts[2] << 8) | networkParts[3]) >>> 0;

  // Create mask
  const mask = prefix === 0 ? 0 : (~((1 << (32 - prefix)) - 1)) >>> 0;

  return (ipInt & mask) === (networkInt & mask);
}

/**
 * IPv6 CIDR matching using BigInt for 128-bit addresses
 */
function matchCidrV6(ip: string, network: string, prefix: number): boolean {
  try {
    const ipBigInt = ipv6ToBigInt(expandIpv6(ip));
    const networkBigInt = ipv6ToBigInt(expandIpv6(network));

    // Create 128-bit mask
    const mask = prefix === 0 ? 0n : ((1n << 128n) - 1n) << BigInt(128 - prefix);

    return (ipBigInt & mask) === (networkBigInt & mask);
  } catch {
    return false;
  }
}

/**
 * Expand abbreviated IPv6 address to full form
 */
function expandIpv6(ip: string): string {
  // Handle :: expansion
  if (ip.includes("::")) {
    const parts = ip.split("::");
    const left = parts[0] ? parts[0].split(":") : [];
    const right = parts[1] ? parts[1].split(":") : [];
    const missing = 8 - left.length - right.length;
    const middle = Array(missing).fill("0000");
    const expanded = [...left, ...middle, ...right];
    return expanded.map(p => p.padStart(4, "0")).join(":");
  }

  return ip.split(":").map(p => p.padStart(4, "0")).join(":");
}

/**
 * Convert expanded IPv6 to BigInt
 */
function ipv6ToBigInt(ip: string): bigint {
  const parts = ip.split(":");
  let result = 0n;
  for (const part of parts) {
    result = (result << 16n) | BigInt(parseInt(part, 16));
  }
  return result;
}

/**
 * Get all exceptions (for API)
 */
export function getAllExceptions(): ExceptionsConfig {
  return loadExceptions();
}

// ============================================
// In-memory storage for login attempts
// ============================================

interface LoginAttempt {
  timestamp: Date;
  username: string;
  ipAddress: string;
  success: boolean;
}

// Store failed login attempts in memory (keyed by IP)
const failedLoginAttempts = new Map<string, LoginAttempt[]>();

// Time window for brute force detection (configurable, default 600 seconds = 10 minutes)
export const BRUTE_FORCE_WINDOW_SECONDS = parseInt(process.env.BRUTE_FORCE_WINDOW_SECONDS || "600", 10);
const BRUTE_FORCE_WINDOW_MS = BRUTE_FORCE_WINDOW_SECONDS * 1000;

/**
 * Record a login attempt in memory
 */
export function recordLoginAttempt(attempt: LoginAttempt): void {
  // Only store failed attempts (for brute force detection)
  if (attempt.success) {
    return;
  }

  const existing = failedLoginAttempts.get(attempt.ipAddress) || [];
  existing.push(attempt);
  failedLoginAttempts.set(attempt.ipAddress, existing);
}

/**
 * Get count of recent failed logins from an IP
 */
export function getRecentFailedLoginCount(ipAddress: string): number {
  const attempts = failedLoginAttempts.get(ipAddress) || [];
  const cutoff = Date.now() - BRUTE_FORCE_WINDOW_MS;

  return attempts.filter(a => a.timestamp.getTime() > cutoff).length;
}

// ============================================
// In-memory storage for alert deduplication
// ============================================

// Key format: "alertType:username:ipAddress"
const recentAlerts = new Map<string, number>(); // value = timestamp

// Alert dedup window (5 minutes)
const ALERT_DEDUP_WINDOW_MS = 5 * 60 * 1000;

/**
 * Check if similar alert was recently sent
 */
export function hasRecentAlert(alertType: string, username: string, ipAddress: string): boolean {
  const key = `${alertType}:${username}:${ipAddress}`;
  const lastSent = recentAlerts.get(key);

  if (!lastSent) return false;

  return Date.now() - lastSent < ALERT_DEDUP_WINDOW_MS;
}

/**
 * Record that an alert was sent
 */
export function recordAlert(alertType: string, username: string, ipAddress: string): void {
  const key = `${alertType}:${username}:${ipAddress}`;
  recentAlerts.set(key, Date.now());
}

// ============================================
// Cleanup old data from memory
// ============================================

function cleanupMemory(): void {
  const loginCutoff = Date.now() - BRUTE_FORCE_WINDOW_MS;
  const alertCutoff = Date.now() - ALERT_DEDUP_WINDOW_MS;

  // Cleanup login attempts
  for (const [ip, attempts] of failedLoginAttempts.entries()) {
    const recent = attempts.filter(a => a.timestamp.getTime() > loginCutoff);
    if (recent.length === 0) {
      failedLoginAttempts.delete(ip);
    } else {
      failedLoginAttempts.set(ip, recent);
    }
  }

  // Cleanup alerts
  for (const [key, timestamp] of recentAlerts.entries()) {
    if (timestamp < alertCutoff) {
      recentAlerts.delete(key);
    }
  }
}

// Cleanup every minute
setInterval(cleanupMemory, 60 * 1000);
