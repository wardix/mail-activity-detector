import { parsePostfixLog } from "./postfix";
import { parseCourierLog } from "./courier";
import type { ParsedLoginAttempt } from "./postfix";

export type { ParsedLoginAttempt };

/**
 * Parse a syslog timestamp to Date object
 * Example: "Jan 19 10:15:00" -> Date object (year from current year)
 */
export function parseSyslogTimestamp(log: string): Date | null {
    // Match syslog timestamp format: "Jan 19 10:15:00"
    const match = log.match(/^(\w{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})/);
    if (!match) {
        return null;
    }

    const months: Record<string, number> = {
        Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5,
        Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11,
    };

    const month = months[match[1]];
    const day = parseInt(match[2], 10);
    const hour = parseInt(match[3], 10);
    const minute = parseInt(match[4], 10);
    const second = parseInt(match[5], 10);

    const now = new Date();
    const year = now.getFullYear();

    return new Date(year, month, day, hour, minute, second);
}

/**
 * Parse log message and detect service type automatically
 */
export function parseLog(log: string): ParsedLoginAttempt | null {
    const timestamp = parseSyslogTimestamp(log) || new Date();

    // Try Postfix parser first
    if (log.includes("postfix") || log.includes("sasl")) {
        const result = parsePostfixLog(log, timestamp);
        if (result) return result;
    }

    // Try Courier-IMAP parser
    if (log.includes("imapd") || log.includes("pop3d") || log.includes("LOGIN")) {
        const result = parseCourierLog(log, timestamp);
        if (result) return result;
    }

    // Try both parsers as fallback
    const postfixResult = parsePostfixLog(log, timestamp);
    if (postfixResult) return postfixResult;

    const courierResult = parseCourierLog(log, timestamp);
    if (courierResult) return courierResult;

    return null;
}
