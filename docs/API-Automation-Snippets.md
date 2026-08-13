# Security Onion — API & Automation Snippets

> **Reference document for `securityonionrameen` lab**  
> Covers: internal Elasticsearch queries (eval-compatible) and official Connect API reference (Pro only)

---

## 1. Internal Elasticsearch Query via `so-elasticsearch-query`

Available in eval mode. Run directly on the SO node as a user with sudo access.

### 1.1 Fetch Recent Alerts (Python)

```python
# fetch_alerts.py
# Run on securityonionrameen: python3 fetch_alerts.py
# Queries the internal Elasticsearch alerts index and prints the 5 most recent alerts

import json
import subprocess

def query_so_alerts():
    command = [
        "sudo", "so-elasticsearch-query",
        ".ds-logs-detections.alerts-so-2026.08.10-000001/_search?pretty",
        "-d", json.dumps({
            "size": 5,
            "_source": ["@timestamp", "rule.name"],
            "sort": [{"@timestamp": {"order": "desc"}}]
        })
    ]

    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        data = json.loads(result.stdout)

        print(f"[+] Total Alerts Found: {data['hits']['total']['value']}\n")
        print(f"{'TIMESTAMP':<28} | {'RULE NAME'}")
        print("-" * 75)

        for hit in data['hits']['hits']:
            source = hit['_source']
            ts = source.get('@timestamp', 'N/A')
            rule = source.get('rule', {}).get('name', 'N/A')
            print(f"{ts:<28} | {rule}")

    except Exception as e:
        print(f"[-] Error querying alerts: {e}")

if __name__ == "__main__":
    query_so_alerts()
```

**Output observed:**
[+] Total Alerts Found: 12

TIMESTAMP | RULE NAME

2026-08-12T18:59:40.000Z | Security Onion - Grid Node Login Failure (SSH)
2026-08-12T18:59:39.000Z | Security Onion - Grid Node Login Failure (SSH)
2026-08-12T18:59:38.000Z | Security Onion - Grid Node Login Failure (SSH)
2026-08-12T18:36:51.000Z | Security Onion - SOC Login Failure
2026-08-11T16:27:24.000Z | Security Onion - SOC Login Failure

---

### 1.2 Query Specific Alert by Rule Name (curl)

```bash
# Run on securityonionrameen
sudo so-elasticsearch-query \
  ".ds-logs-detections.alerts-so-*/_search?pretty" \
  -d '{
    "size": 5,
    "query": {
      "match": {
        "rule.name": "CUSTOM LAB HTTP USER AGENT"
      }
    },
    "_source": ["@timestamp", "rule.name", "source.ip", "destination.ip", "destination.port"]
  }'
```

---

### 1.3 Count Alerts Grouped by Rule Name

```bash
sudo so-elasticsearch-query \
  ".ds-logs-detections.alerts-so-*/_search?pretty" \
  -d '{
    "size": 0,
    "aggs": {
      "by_rule": {
        "terms": {
          "field": "rule.name",
          "size": 10
        }
      }
    }
  }'
```

---

### 1.4 Query Zeek HTTP Logs (curl)

```bash
sudo so-elasticsearch-query \
  "logs-zeek.http-so/_search?pretty" \
  -d '{
    "size": 5,
    "query": {
      "match": {
        "source.ip": "172.16.50.2"
      }
    },
    "_source": ["@timestamp", "http.request.method", "url.original", "user_agent.original", "destination.ip"]
  }'
```

---

## 2. Official Connect API — Pro License Required

> The Connect API is **not available in eval mode**. The following is documented for reference and future production use. Requires SO 2.4.120+ with an active Pro license and an API client created under Administration → API Clients.

**Official docs:** https://docs.securityonion.net/en/2.4/connect.html

---

### 2.1 Authenticate — Obtain Bearer Token

```bash
curl --cacert ca.crt \
  -X POST \
  -u "CLIENT_ID:CLIENT_SECRET" \
  https://BASE_URL/oauth2/token \
  -d grant_type=client_credentials
```

**Response:**
```json
{
  "access_token": "eyJhbGciOi...",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

---

### 2.2 Get Grid Info

```bash
curl --cacert ca.crt \
  -X GET \
  -H "Authorization: Bearer ACCESS_TOKEN" \
  https://BASE_URL/connect/info
```

---

### 2.3 Fetch Recent Alerts via Connect API

```bash
curl --cacert ca.crt \
  -X GET \
  -H "Authorization: Bearer ACCESS_TOKEN" \
  "https://BASE_URL/connect/events?dataset=suricata.alert&size=10"
```

---

### 2.4 Create a Case via Connect API

```bash
curl --cacert ca.crt \
  -X POST \
  -H "Authorization: Bearer ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  https://BASE_URL/connect/cases \
  -d '{
    "title": "Suspicious HTTP User-Agent Detected",
    "description": "Custom SOC-TEST-AGENT User-Agent observed from 172.16.50.2",
    "severity": "low",
    "status": "open"
  }'
```

---

### 2.5 Python Wrapper — Connect API Alert Fetch (Pro Reference)

```python
# connect_api_alerts.py
# FOR PRO DEPLOYMENTS ONLY — requires valid CLIENT_ID and CLIENT_SECRET

import requests

BASE_URL = "https://192.168.56.102"
CLIENT_ID = "your_client_id"
CLIENT_SECRET = "your_client_secret"
CA_CERT = "/path/to/ca.crt"

def get_token():
    resp = requests.post(
        f"{BASE_URL}/oauth2/token",
        auth=(CLIENT_ID, CLIENT_SECRET),
        data={"grant_type": "client_credentials"},
        verify=CA_CERT
    )
    return resp.json()["access_token"]

def fetch_alerts(token, size=10):
    headers = {"Authorization": f"Bearer {token}"}
    resp = requests.get(
        f"{BASE_URL}/connect/events",
        headers=headers,
        params={"dataset": "suricata.alert", "size": size},
        verify=CA_CERT
    )
    return resp.json()

if __name__ == "__main__":
    token = get_token()
    alerts = fetch_alerts(token)
    for alert in alerts.get("hits", {}).get("hits", []):
        src = alert["_source"]
        print(f"{src.get('@timestamp')} | {src.get('rule', {}).get('name')}")
```

---

## 3. Eval Mode vs Pro API Capabilities

| Capability                                                | Eval Mode      | Pro (Connect API) |
|-----------------------------------------------------------|----------------|-------------------|
| Query Elasticsearch directly via `so-elasticsearch-query` |  Yes           |  Yes              |
| Fetch alerts programmatically                             | Via subprocess |  Via REST         |
| Create cases via API                                      | No             |  Yes              |
| Interact with Onion AI via API                            |  No            |   Yes             |
| External integration (SOAR, ticketing)                    |  No            |  Yes              |
| OAuth2 bearer token auth                                  |  No            |  Yes              |

---