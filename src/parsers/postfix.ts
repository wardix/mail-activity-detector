export interface ParsedLoginAttempt {
    timestamp: Date;
    username: string;
    ipAddress: string;
    success: boolean;
    service: "postfix" | "courier-imap";
    rawLog: string;
}

/**
 * Parse Postfix SASL authentication logs
 * 
 * Success patterns:
 * - "client=unknown[IP], sasl_method=LOGIN, sasl_username=user@example.com"
 * 
 * Failure patterns:
 * - "warning: unknown[IP]: SASL LOGIN authentication failed"
 * - "warning: SASL authentication failure: ..."
 */
export function parsePostfixLog(log: string, logTimestamp?: Date): ParsedLoginAttempt | null {
    const timestamp = logTimestamp || new Date();

    // Pattern for successful SASL login
    // Example: client=unknown[203.0.113.1], sasl_method=LOGIN, sasl_username=user@example.com
    const successMatch = log.match(
        /client=\S+\[([^\]]+)\].*sasl_method=\w+,\s*sasl_username=(\S+)/i
    );

    if (successMatch) {
        return {
            timestamp,
            ipAddress: successMatch[1],
            username: successMatch[2],
            success: true,
            service: "postfix",
            rawLog: log,
        };
    }

    // Pattern for failed SASL login
    // Example: warning: unknown[203.0.113.1]: SASL LOGIN authentication failed
    const failMatch = log.match(
        /warning:\s*\S*\[([^\]]+)\]:\s*SASL\s+\w+\s+authentication\s+failed/i
    );

    if (failMatch) {
        // For failed attempts, we might not have username
        // Try to extract from previous log context if available
        return {
            timestamp,
            ipAddress: failMatch[1],
            username: "unknown", // Will be updated if we can correlate with other logs
            success: false,
            service: "postfix",
            rawLog: log,
        };
    }

    // Alternative failure pattern with username
    // Example: SASL PLAIN authentication failed: user@example.com
    const failWithUserMatch = log.match(
        /warning:\s*\S*\[([^\]]+)\].*SASL.*failed.*?(\S+@\S+)/i
    );

    if (failWithUserMatch) {
        return {
            timestamp,
            ipAddress: failWithUserMatch[1],
            username: failWithUserMatch[2],
            success: false,
            service: "postfix",
            rawLog: log,
        };
    }

    return null;
}
