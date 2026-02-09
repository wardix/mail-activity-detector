import { checkAccountException, isLocationCheckSkipped } from "../db";
import { getCountryCode } from "../services/geoip";
import { sendAlert } from "../services/webhook";
import type { ParsedLoginAttempt } from "../parsers";

// Allowed countries for normal login (configurable, comma-separated)
// Default: ID,MY,SG (Indonesia, Malaysia, Singapore)
const ALLOWED_COUNTRIES_LIST = (process.env.ALLOWED_COUNTRIES || "ID,MY,SG")
    .split(",")
    .map(c => c.trim().toUpperCase());
const ALLOWED_COUNTRIES = new Set(ALLOWED_COUNTRIES_LIST);

/**
 * Check if a successful login is from an unusual location
 * Returns true if alert was sent
 */
export async function detectUnusualLocation(
    attempt: ParsedLoginAttempt
): Promise<boolean> {
    // Only check successful logins
    if (!attempt.success) {
        return false;
    }

    // Check if IP should skip location check (e.g., cloud provider IPs)
    if (isLocationCheckSkipped(attempt.ipAddress)) {
        return false;
    }

    // Get country code for the IP
    const countryCode = await getCountryCode(attempt.ipAddress);

    // Skip if we couldn't determine country (private IP, API error, etc.)
    if (!countryCode) {
        console.log(`Could not determine country for IP ${attempt.ipAddress}`);
        return false;
    }

    // Check if country is in allowed list
    if (ALLOWED_COUNTRIES.has(countryCode)) {
        return false;
    }

    // Check for account exception (now from JSON file)
    if (checkAccountException(attempt.username, countryCode)) {
        console.log(
            `Account exception found: ${attempt.username} allowed from ${countryCode}`
        );
        return false;
    }

    // Unusual location detected - send alert
    console.log(
        `Unusual location detected: ${attempt.username} from ${countryCode} (IP: ${attempt.ipAddress})`
    );

    const sent = await sendAlert({
        alertType: "unusual_location",
        username: attempt.username,
        ipAddress: attempt.ipAddress,
        countryCode,
        timestamp: attempt.timestamp,
        details: {
            service: attempt.service,
            allowedCountries: Array.from(ALLOWED_COUNTRIES),
        },
    });

    return sent;
}
