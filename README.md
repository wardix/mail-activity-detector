# Mail Activity Detector

Web service untuk mendeteksi unusual account activity pada mail server (Postfix + Courier-IMAP).

## Features

- ✅ **Log Ingestion** - Menerima log via HTTP dari rsyslog omhttp
- ✅ **Unusual Location Detection** - Alert jika login sukses dari negara selain ID, MY, SG
- ✅ **Brute Force Detection** - Alert jika 3+ failed login dalam 10 menit dari IP yang sama
- ✅ **Account Exceptions** - Whitelist account tertentu untuk login dari negara tertentu
- ✅ **Webhook Notifications** - Kirim alert ke webhook (Telegram, Slack, dll)
- ✅ **Alert Deduplication** - Tidak mengirim alert yang sama dalam 5 menit

## Quick Start

```bash
# Install dependencies
bun install

# Set environment variables
export PORT=3000
export GEOIP_API_URL=http://your-geoip-service/geoip

# Run the service
bun run dev
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | 3000 | Server port |
| `DB_PATH` | `./data/activity.db` | SQLite database path |
| `GEOIP_API_URL` | `http://localhost:3001/geoip` | External GeoIP API endpoint |

## API Endpoints

### Log Ingestion

```bash
# Single log
POST /logs
Content-Type: application/json
{"message": "Jan 19 10:15:00 mail postfix/smtpd[1234]: client=unknown[1.2.3.4], sasl_method=LOGIN, sasl_username=user@example.com"}

# Batch logs (rsyslog batch.format=jsonarray)
POST /logs/batch
Content-Type: application/json
[{"message": "..."}, {"message": "..."}]
```

### Exception Management

```bash
# List exceptions
GET /exceptions

# Add exception
POST /exceptions
{"username": "admin@example.com", "countryCode": "US", "note": "Travels frequently"}

# Remove exception
DELETE /exceptions/:id
```

### Webhook Configuration

```bash
# List webhooks
GET /webhooks

# Add webhook
POST /webhooks
{"name": "Telegram NOC", "url": "https://api.telegram.org/botXXX/sendMessage"}

# Remove webhook
DELETE /webhooks/:id
```

## rsyslog Configuration

```
module(load="omhttp")

template(name="json_log" type="string" 
  string="{\"message\":\"%rawmsg:::json%\"}")

action(
  type="omhttp"
  server="localhost"
  serverport="3000"
  restpath="logs"
  template="json_log"
)
```

## Webhook Payload

Default alert payload:

```json
{
  "alert_type": "unusual_location",
  "username": "user@example.com",
  "ip_address": "1.2.3.4",
  "country_code": "US",
  "timestamp": "2026-01-19T10:15:00.000Z",
  "message": "🚨 Unusual Login Detected!\n\nUser: user@example.com\nIP: 1.2.3.4\nCountry: US\nTime: 2026-01-19T10:15:00.000Z",
  "details": {...}
}
```

## License

MIT
