import { getRecentFailedLoginCount } from "../db";
import { getCountryCode } from "../services/geoip";
import { sendAlert } from "../services/webhook";
import type { ParsedLoginAttempt } from "../parsers";

// Brute force threshold
const FAILED_LOGIN_THRESHOLD = 3;

/**
 * Check if there's a brute force attack from an IP
 * Triggers when 3+ failed logins occur within 10 minutes from same IP
 * Returns true if alert was sent
 */
export async function detectBruteForce(
    attempt: ParsedLoginAttempt
): Promise<boolean> {
    // Only check failed logins
    if (attempt.success) {
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
            windowMinutes: 10,
        },
    });

    return sent;
}
