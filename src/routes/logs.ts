import { Hono } from "hono";
import { parseLog, type ParsedLoginAttempt } from "../parsers";
import { recordLoginAttempt } from "../db";
import { getCountryCode } from "../services/geoip";
import { detectUnusualLocation } from "../detectors/unusual-location";
import { detectBruteForce } from "../detectors/brute-force";

const logs = new Hono();

// Tags that indicate mail login logs (configurable)
const ALLOWED_TAGS = (process.env.LOG_TAGS || "postfix/smtpd,postfix/submission,imapd,pop3d")
    .split(",")
    .map(t => t.trim().toLowerCase());

interface LogPayload {
    timestamp?: string;  // RFC3339 from rsyslog
    host?: string;
    severity?: string;
    facility?: string;
    tag?: string;
    message?: string;
    msg?: string;
    rawmsg?: string;
}

/**
 * Check if tag matches allowed mail service tags
 */
function isRelevantTag(tag: string | undefined): boolean {
    if (!tag) return true; // If no tag, skip filter and process anyway

    const normalizedTag = tag.toLowerCase();
    return ALLOWED_TAGS.some(allowed => normalizedTag.includes(allowed));
}

/**
 * Parse timestamp from rsyslog payload
 */
function parsePayloadTimestamp(timestamp: string | undefined): Date {
    if (!timestamp) return new Date();

    try {
        const parsed = new Date(timestamp);
        if (!isNaN(parsed.getTime())) {
            return parsed;
        }
    } catch {
        // Fall back to current time
    }

    return new Date();
}

/**
 * POST /logs
 * Receive logs from rsyslog omhttp
 */
logs.post("/", async (c) => {
    try {
        const body = await c.req.json<LogPayload>();

        // Filter by tag if present
        if (!isRelevantTag(body.tag)) {
            return c.json({ status: "ignored", reason: "irrelevant tag", tag: body.tag });
        }

        const logMessage = body.message || body.msg || body.rawmsg;

        if (!logMessage) {
            return c.json({ error: "No log message found" }, 400);
        }

        // Use timestamp from payload if available
        const payloadTimestamp = parsePayloadTimestamp(body.timestamp);

        const parsed = parseLog(logMessage);

        if (!parsed) {
            return c.json({ status: "ignored", reason: "not a login log" });
        }

        // Override timestamp with payload timestamp (more accurate)
        parsed.timestamp = payloadTimestamp;

        // Get country code for the IP
        const countryCode = await getCountryCode(parsed.ipAddress);

        // Record login attempt in memory (for brute force detection)
        recordLoginAttempt({
            timestamp: parsed.timestamp,
            username: parsed.username,
            ipAddress: parsed.ipAddress,
            success: parsed.success,
        });

        // Run detectors
        const alerts: string[] = [];

        if (await detectUnusualLocation(parsed)) {
            alerts.push("unusual_location");
        }

        if (await detectBruteForce(parsed)) {
            alerts.push("brute_force");
        }

        return c.json({
            status: "processed",
            parsed: {
                username: parsed.username,
                ip: parsed.ipAddress,
                country: countryCode,
                success: parsed.success,
                service: parsed.service,
                timestamp: parsed.timestamp.toISOString(),
            },
            alerts,
        });
    } catch (error) {
        console.error("Error processing log:", error);
        return c.json({ error: "Failed to process log" }, 500);
    }
});

/**
 * POST /logs/batch
 * Receive batch of logs from rsyslog omhttp
 */
logs.post("/batch", async (c) => {
    try {
        const body = await c.req.json<LogPayload[]>();

        if (!Array.isArray(body)) {
            return c.json({ error: "Expected array of log entries" }, 400);
        }

        const results = {
            total: body.length,
            processed: 0,
            alerts: 0,
            ignored: 0,
        };

        for (const entry of body) {
            // Filter by tag if present
            if (!isRelevantTag(entry.tag)) {
                results.ignored++;
                continue;
            }

            const logMessage = entry.message || entry.msg || entry.rawmsg;

            if (!logMessage) {
                results.ignored++;
                continue;
            }

            const parsed = parseLog(logMessage);

            if (!parsed) {
                results.ignored++;
                continue;
            }

            // Override timestamp with payload timestamp
            parsed.timestamp = parsePayloadTimestamp(entry.timestamp);

            // Record in memory
            recordLoginAttempt({
                timestamp: parsed.timestamp,
                username: parsed.username,
                ipAddress: parsed.ipAddress,
                success: parsed.success,
            });

            if (await detectUnusualLocation(parsed)) {
                results.alerts++;
            }

            if (await detectBruteForce(parsed)) {
                results.alerts++;
            }

            results.processed++;
        }

        return c.json({ status: "processed", ...results });
    } catch (error) {
        console.error("Error processing batch:", error);
        return c.json({ error: "Failed to process batch" }, 500);
    }
});

export default logs;
