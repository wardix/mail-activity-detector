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
  bodyTemplate: string | null;
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
// Account exceptions from JSON file
// ============================================

export interface AccountException {
  username: string;
  countryCode: string;
  note?: string;
}

let exceptionsCache: AccountException[] | null = null;
let exceptionsCacheTime = 0;
const CACHE_TTL_MS = 60 * 1000; // Reload every 1 minute

/**
 * Load account exceptions from JSON file (with caching)
 */
function loadExceptions(): AccountException[] {
  const now = Date.now();

  // Return cached if still valid
  if (exceptionsCache && now - exceptionsCacheTime < CACHE_TTL_MS) {
    return exceptionsCache;
  }

  try {
    if (!existsSync(EXCEPTIONS_PATH)) {
      console.warn(`Exceptions config not found: ${EXCEPTIONS_PATH}`);
      exceptionsCache = [];
      exceptionsCacheTime = now;
      return [];
    }

    const content = readFileSync(EXCEPTIONS_PATH, "utf-8");
    exceptionsCache = JSON.parse(content) as AccountException[];
    exceptionsCacheTime = now;

    return exceptionsCache;
  } catch (error) {
    console.error("Failed to load exceptions config:", error);
    return [];
  }
}

/**
 * Check if an account has exception for a country
 */
export function checkAccountException(username: string, countryCode: string): boolean {
  const exceptions = loadExceptions();
  return exceptions.some(
    e => e.username === username && e.countryCode === countryCode
  );
}

/**
 * Get all exceptions (for API)
 */
export function getAllExceptions(): AccountException[] {
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

// Time window for brute force detection (10 minutes)
const BRUTE_FORCE_WINDOW_MS = 10 * 60 * 1000;

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
