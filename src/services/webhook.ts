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
 * Get template variables for replacement
 */
function getTemplateVariables(payload: AlertPayload): Record<string, string> {
    return {
        "{{alert_type}}": payload.alertType,
        "{{username}}": payload.username,
        "{{ip_address}}": payload.ipAddress,
        "{{country_code}}": payload.countryCode || "unknown",
        "{{timestamp}}": payload.timestamp.toISOString(),
        "{{message}}": formatAlertMessage(payload),
    };
}

/**
 * Replace template variables in a string
 */
function replaceTemplateVars(text: string, variables: Record<string, string>): string {
    let result = text;
    for (const [key, value] of Object.entries(variables)) {
        result = result.replace(new RegExp(key.replace(/[{}]/g, "\\$&"), "g"), value);
    }
    return result;
}

/**
 * Recursively replace template variables in an object
 */
function replaceTemplateInObject(obj: unknown, variables: Record<string, string>): unknown {
    if (typeof obj === "string") {
        return replaceTemplateVars(obj, variables);
    }

    if (Array.isArray(obj)) {
        return obj.map(item => replaceTemplateInObject(item, variables));
    }

    if (obj !== null && typeof obj === "object") {
        const result: Record<string, unknown> = {};
        for (const [key, value] of Object.entries(obj)) {
            result[key] = replaceTemplateInObject(value, variables);
        }
        return result;
    }

    return obj;
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

    const variables = getTemplateVariables(payload);

    // Handle object template (new format)
    if (typeof webhook.bodyTemplate === "object") {
        return replaceTemplateInObject(webhook.bodyTemplate, variables) as Record<string, unknown>;
    }

    // Handle string template (legacy format)
    try {
        const body = replaceTemplateVars(webhook.bodyTemplate, variables);
        return JSON.parse(body);
    } catch (error) {
        console.error(`Invalid body template for webhook ${webhook.name}:`, error);
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
        return `Unusual Login Detected!\n\nUser: ${payload.username}\nIP: ${payload.ipAddress}\nCountry: ${payload.countryCode || "unknown"}\nTime: ${payload.timestamp.toISOString()}`;
    }

    if (payload.alertType === "brute_force") {
        const failCount = (payload.details.failedAttempts as number) || 3;
        const windowSeconds = (payload.details.windowSeconds as number) || 600;
        return `Brute Force Attack Detected!\n\nTarget: ${payload.username}\nIP: ${payload.ipAddress}\nCountry: ${payload.countryCode || "unknown"}\nFailed attempts: ${failCount} in last ${windowSeconds} seconds`;
    }

    return `Alert: ${payload.alertType} for ${payload.username}`;
}
