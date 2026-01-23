const GEOIP_API_URL = process.env.GEOIP_API_URL || "http://localhost:3001/lookup?ip=";

// Get custom headers from environment variable (JSON format)
// Example: GEOIP_API_HEADERS='{"Authorization":"Basic YWRtaW46c2VjcmV0"}'
function getGeoipHeaders(): Record<string, string> {
    const headersEnv = process.env.GEOIP_API_HEADERS;
    if (!headersEnv) return {};

    try {
        return JSON.parse(headersEnv);
    } catch {
        console.error("Invalid GEOIP_API_HEADERS JSON format");
        return {};
    }
}

// Simple in-memory cache with TTL
const cache = new Map<string, { countryCode: string | null; expiry: number }>();
const CACHE_TTL_MS = 60 * 60 * 1000; // 1 hour

interface GeoipResponse {
    countryCode: string;
}

/**
 * Get country code for an IP address using external API
 * Returns null if lookup fails or IP is private/local
 */
export async function getCountryCode(ip: string): Promise<string | null> {
    // Skip private/local IPs
    if (isPrivateIP(ip)) {
        return null;
    }

    // Check cache first
    const cached = cache.get(ip);
    if (cached && cached.expiry > Date.now()) {
        return cached.countryCode;
    }

    try {
        // Directly append IP to configured URL
        const response = await fetch(`${GEOIP_API_URL}${ip}`, {
            headers: getGeoipHeaders(),
        });

        if (!response.ok) {
            console.error(`GeoIP API error: ${response.status} for IP ${ip}`);
            return null;
        }

        const data = (await response.json()) as GeoipResponse;
        const countryCode = data.countryCode || null;

        // Cache the result
        cache.set(ip, {
            countryCode,
            expiry: Date.now() + CACHE_TTL_MS,
        });

        return countryCode;
    } catch (error) {
        console.error(`GeoIP lookup failed for ${ip}:`, error);
        return null;
    }
}

/**
 * Check if IP is private/local (RFC 1918, loopback, etc.)
 */
function isPrivateIP(ip: string): boolean {
    // IPv4 private ranges
    if (
        ip.startsWith("10.") ||
        ip.startsWith("192.168.") ||
        ip.startsWith("127.") ||
        ip.startsWith("169.254.") ||
        ip === "localhost"
    ) {
        return true;
    }

    // 172.16.0.0 - 172.31.255.255
    if (ip.startsWith("172.")) {
        const secondOctet = parseInt(ip.split(".")[1], 10);
        if (secondOctet >= 16 && secondOctet <= 31) {
            return true;
        }
    }

    // IPv6 loopback and link-local
    if (ip === "::1" || ip.startsWith("fe80:") || ip.startsWith("fc") || ip.startsWith("fd")) {
        return true;
    }

    return false;
}

/**
 * Clear expired entries from cache (call periodically)
 */
export function cleanupCache(): void {
    const now = Date.now();
    for (const [key, value] of cache.entries()) {
        if (value.expiry < now) {
            cache.delete(key);
        }
    }
}

// Cleanup cache every 10 minutes
setInterval(cleanupCache, 10 * 60 * 1000);
