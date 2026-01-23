import { getEnabledWebhooks, hasRecentAlert, recordAlert, type WebhookConfig } from "../db";

interface AlertPayload {
    alertType: "unusual_location" | "brute_force";
    username: string;
    ipAddress: string;
    countryCode: string | null;
    timestamp: Date;
    details: Record<string, unknown>;
}

/**
 * Send alert to all enabled webhooks
 * Returns true if at least one webhook succeeded
 */
export async function sendAlert(payload: AlertPayload): Promise<boolean> {
    // Check for duplicate alert (sent in last 5 minutes) - from memory
    if (hasRecentAlert(payload.alertType, payload.username, payload.ipAddress)) {
        console.log(`Skipping duplicate alert for ${payload.username} from ${payload.ipAddress}`);
        return false;
    }

    const webhooks = getEnabledWebhooks();

    if (webhooks.length === 0) {
        console.warn("No enabled webhooks configured");
        return false;
    }

    let success = false;

    for (const webhook of webhooks) {
        try {
            const body = formatWebhookBody(webhook, payload);
            const headers: Record<string, string> = {
                "Content-Type": "application/json",
            };

            // Add custom headers if present
            if (webhook.headers) {
                Object.assign(headers, webhook.headers);
            }

            const response = await fetch(webhook.url, {
                method: webhook.method || "POST",
                headers,
                body: JSON.stringify(body),
            });

            if (response.ok) {
                console.log(`Alert sent to ${webhook.name}: ${payload.alertType}`);
                success = true;
            } else {
                console.error(`Webhook ${webhook.name} failed: ${response.status}`);
            }
        } catch (error) {
            console.error(`Webhook ${webhook.name} error:`, error);
        }
    }

    // Record the alert in memory for deduplication
    if (success) {
        recordAlert(payload.alertType, payload.username, payload.ipAddress);
    }

    return success;
}

/**
 * Format webhook body using template or default format
 */
function formatWebhookBody(
    webhook: WebhookConfig,
    payload: AlertPayload
): Record<string, unknown> {
    // If no template, use default format
    if (!webhook.bodyTemplate) {
        return {
            alert_type: payload.alertType,
            username: payload.username,
            ip_address: payload.ipAddress,
            country_code: payload.countryCode,
            timestamp: payload.timestamp.toISOString(),
            message: formatAlertMessage(payload),
            details: payload.details,
        };
    }

    // Simple template replacement
    try {
        let body = webhook.bodyTemplate;

        // Replace placeholders
        body = body.replace(/\{\{alert_type\}\}/g, payload.alertType);
        body = body.replace(/\{\{username\}\}/g, payload.username);
        body = body.replace(/\{\{ip_address\}\}/g, payload.ipAddress);
        body = body.replace(/\{\{country_code\}\}/g, payload.countryCode || "unknown");
        body = body.replace(/\{\{timestamp\}\}/g, payload.timestamp.toISOString());
        body = body.replace(/\{\{message\}\}/g, formatAlertMessage(payload));

        return JSON.parse(body);
    } catch {
        console.error(`Invalid body template for webhook ${webhook.name}`);
        return {
            message: formatAlertMessage(payload),
        };
    }
}

/**
 * Format human-readable alert message
 */
function formatAlertMessage(payload: AlertPayload): string {
    if (payload.alertType === "unusual_location") {
        return `🚨 Unusual Login Detected!\n\nUser: ${payload.username}\nIP: ${payload.ipAddress}\nCountry: ${payload.countryCode || "unknown"}\nTime: ${payload.timestamp.toISOString()}`;
    }

    if (payload.alertType === "brute_force") {
        const failCount = (payload.details.failedAttempts as number) || 3;
        return `🔐 Brute Force Attack Detected!\n\nTarget: ${payload.username}\nIP: ${payload.ipAddress}\nCountry: ${payload.countryCode || "unknown"}\nFailed attempts: ${failCount} in last 10 minutes`;
    }

    return `Alert: ${payload.alertType} for ${payload.username}`;
}
