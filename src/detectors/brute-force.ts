import { getRecentFailedLoginCount, BRUTE_FORCE_WINDOW_SECONDS, isIpWhitelisted } from "../db";
import { getCountryCode } from "../services/geoip";
import { sendAlert } from "../services/webhook";
import type { ParsedLoginAttempt } from "../parsers";

// Brute force threshold (configurable, default 3)
const FAILED_LOGIN_THRESHOLD = parseInt(process.env.BRUTE_FORCE_THRESHOLD || "3", 10);

/**
 * Check if there's a brute force attack from an IP
 * Triggers when threshold failed logins occur within window from same IP
 * Returns true if alert was sent
 */
export async function detectBruteForce(
    attempt: ParsedLoginAttempt
): Promise<boolean> {
    // Only check failed logins
    if (attempt.success) {
        return false;
    }

    // Check if IP is whitelisted
    if (isIpWhitelisted(attempt.ipAddress)) {
        return false;
    }

    // Count recent failed attempts from this IP (from in-memory store)
    const failedCount = getRecentFailedLoginCount(attempt.ipAddress);

    // Check if threshold reached (including current attempt)
    if (failedCount + 1 < FAILED_LOGIN_THRESHOLD) {
        return false;
    }

    // Brute force detected
    console.log(
        `Brute force detected: ${failedCount + 1} failed attempts from ${attempt.ipAddress}`
    );

    // Get country code for reporting
    const countryCode = await getCountryCode(attempt.ipAddress);

    const sent = await sendAlert({
        alertType: "brute_force",
        username: attempt.username,
        ipAddress: attempt.ipAddress,
        countryCode,
        timestamp: attempt.timestamp,
        details: {
            failedAttempts: failedCount + 1,
            service: attempt.service,
            windowSeconds: BRUTE_FORCE_WINDOW_SECONDS,
        },
    });

    return sent;
}
