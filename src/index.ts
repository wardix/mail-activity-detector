import { Hono } from "hono";
import { logger } from "hono/logger";

// Import routes
import logs from "./routes/logs";
import exceptions from "./routes/exceptions";

const app = new Hono();

// Middleware
app.use("*", logger());

// Health check
app.get("/", (c) => {
    return c.json({
        service: "mail-activity-detector",
        version: "1.0.0",
        status: "running",
        endpoints: {
            logs: "POST /logs - Receive logs from rsyslog",
            logsBatch: "POST /logs/batch - Receive batch of logs",
            exceptions: "GET /exceptions - View account exceptions",
        },
    });
});

// Mount routes
app.route("/logs", logs);
app.route("/exceptions", exceptions);

// Start server
const port = parseInt(process.env.PORT || "3000", 10);

console.log(`
╔══════════════════════════════════════════════════════════════╗
║            Mail Activity Detector Service                    ║
╠══════════════════════════════════════════════════════════════╣
║  Server running on http://localhost:${port.toString().padEnd(26)}║
║                                                              ║
║  Endpoints:                                                  ║
║    POST /logs         - Receive logs from rsyslog            ║
║    POST /logs/batch   - Receive batch of logs                ║
║    GET  /exceptions   - View account exceptions              ║
║                                                              ║
║  Config Files:                                               ║
║    webhooks.json      - Webhook configurations               ║
║    exceptions.json    - Account exceptions whitelist         ║
║                                                              ║
║  Environment Variables:                                      ║
║    PORT               - Server port (default: 3000)          ║
║    WEBHOOKS_PATH      - Webhooks JSON file path              ║
║    EXCEPTIONS_PATH    - Exceptions JSON file path            ║
║    GEOIP_API_URL      - GeoIP API endpoint                   ║
║    GEOIP_API_HEADERS  - GeoIP API headers (JSON)             ║
╚══════════════════════════════════════════════════════════════╝
`);

export default {
    port,
    fetch: app.fetch,
};
