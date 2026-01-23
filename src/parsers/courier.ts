import type { ParsedLoginAttempt } from "./postfix";

/**
 * Parse Courier-IMAP login logs
 * 
 * Success patterns:
 * - "LOGIN, user=user@example.com, ip=[203.0.113.1]"
 * - "imapd: LOGIN, user=user@example.com, ip=[::ffff:203.0.113.1]"
 * 
 * Failure patterns:
 * - "LOGIN FAILED, user=user@example.com, ip=[203.0.113.1]"
 * - "imapd: LOGIN FAILED, ip=[203.0.113.1]"
 */
export function parseCourierLog(log: string, logTimestamp?: Date): ParsedLoginAttempt | null {
    const timestamp = logTimestamp || new Date();

    // Check if this is a courier-imap login log
    if (!log.includes("LOGIN")) {
        return null;
    }

    // Extract IP address - handle both IPv4 and IPv6 mapped addresses
    // ip=[203.0.113.1] or ip=[::ffff:203.0.113.1]
    const ipMatch = log.match(/ip=\[([^\]]+)\]/i);
    if (!ipMatch) {
        return null;
    }

    let ipAddress = ipMatch[1];

    // Convert IPv6-mapped IPv4 to plain IPv4
    // ::ffff:203.0.113.1 -> 203.0.113.1
    if (ipAddress.startsWith("::ffff:")) {
        ipAddress = ipAddress.replace("::ffff:", "");
    }

    // Extract username
    const userMatch = log.match(/user=([^,\s]+)/i);
    const username = userMatch ? userMatch[1] : "unknown";

    // Determine if success or failure
    const isFailure = /LOGIN\s+FAILED/i.test(log);

    return {
        timestamp,
        ipAddress,
        username,
        success: !isFailure,
        service: "courier-imap",
        rawLog: log,
    };
}
