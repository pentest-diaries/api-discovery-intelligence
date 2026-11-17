# APERTURE API Intelligence — Local MVP

An original Noname-inspired **API / NON_API / UNIDENTIFIED** classifier with a browser dashboard. No affiliation with Noname Security or Akamai. **Python standard library only** (Python 3.9+); no pip dependencies, Docker, paid account, or external services.

## Run

macOS/Linux: `./run.sh` (or `python3 server.py`)

Windows: double-click `run.bat` (or `py server.py`)

Open **http://127.0.0.1:8765** and choose **Analyze a file** to inspect `samples/traffic.json`. Optionally compare it with `samples/noname_reference.json` (SYNTHETIC DEMO FILE — NOT A REAL NONAME EXPORT). Correct results directly with **API** or **Not API**; verified corrections are remembered and teach similar predictions. Choose **Pause inspection** to disable new live ingest.

## Live ingestion

Click **Live Traffic**, then POST **structured JSON traffic records** from a gateway, log forwarder, HTTP reverse-proxy connector or SIEM exporter to `http://127.0.0.1:8765/api/ingest`.

Example:

```bash
curl -X POST http://127.0.0.1:8765/api/ingest -H 'Content-Type: application/json' --data '{"traffic":[{"id":"req1","url":"https://example.org/api/v1/users","method":"GET","status":200,"response_headers":{"Content-Type":"application/json"}}]}'
```

The app **does not** automatically capture packets, decrypt TLS, act as an inline reverse proxy, or intercept traffic. Connect a real source to the HTTP ingress. The server defaults to localhost intentionally. For remote forwarding, use a properly authenticated ingress gateway or secure private tunnel, not a publicly exposed unauthenticated port. To listen on all interfaces for a trusted lab, run `python3 server.py --host 0.0.0.0` and restrict with a firewall. Do **not** publish directly to the Internet.

### HTTP API

| Endpoint | Method | Purpose |
|---|---|---|
| `/api/health` | GET | Health / active mode |
| `/api/state` | GET | Dashboard totals, records, comparison and reviews |
| `/api/mode` | POST | `{"mode":"live"}` / `file` / `off` |
| `/api/ingest` | POST | Push JSON while mode is live |
| `/api/upload` | POST | Push JSON while mode is file |
| `/api/compare` | POST | Upload reference classification rows |
| `/api/feedback` | POST | `{"event_id":"evt-001", "label":"API"}` |
| `/api/export` | GET | Download JSON results |

### Accepted JSON

An array of traffic objects or an object containing `traffic`, `records`, `requests`, `events`, `results`, `items`, or `data` array. Each record may include `id`, `url`/`path`, `method`, `status`, `request_headers`, `response_headers`, and `request`/`response` nested objects. If a response `body` is an object/array, it contributes structured-content evidence. Authentication headers are discarded before persistence. Do **not** send sensitive payloads to this local MVP; redact them at the collector.

Reference rows need `id` (best join key) and `label` (`API`, `NON_API`, `UNIDENTIFIED`), or a unique `host` + `method` + `path`. Alias `is_api` (bool) supported. Real Noname exports may require a schema adapter; the included example is synthetic and is not asserted to match a vendor export. A reference file with labels but no shared ID or request locator cannot reliably match rows.

## Classification method and safe feedback

- Explainable features: API/path patterns, REST, GraphQL, SOAP, gRPC, JSON-RPC, request and response media types, methods, browser HTML, static resources, and machine clients.
- Confidence-aware abstention: ambiguous or conflicting records are `UNIDENTIFIED`.
- Confirmed endpoint memory keyed by hostname/method/normalized path; numeric IDs and UUID-like segments become `{id}`.
- Comparison reports reference *agreement*, confusion matrix and per-class precision/recall/F1, **not validated real-world accuracy**.
- Comparison rows are **review candidates only**. They never become training labels without human confirmation.
- Correct a result with **API** or **Not API** in the traffic table. Verified endpoint labels apply immediately to that endpoint; all verified corrections also train shared feature weights so similar traffic can benefit. The bounded update is checked against the reviewed examples and rejected if their accuracy drops. This is not a guarantee of continual improvement or real-world accuracy: review trustworthy labels, and use the optional comparison as a hint rather than ground truth.
- Data stored in `data/inspection.sqlite3`. Delete it while the service is stopped to reset mode, learning history and results.

## Limits / production roadmap

- Initial **MVP**, not feature parity with Akamai API Security. No direct PCAP/TLS inspection, native cloud connectors, shadow domain crawl, OpenAPI specification inference, API sequence analytics, automated attack defense, PII detection, operational RBAC, authenticated multiuser access, multi-node scaling or formal calibration.
- No automatic learning from raw input, model-self-labels, or vendor comparison disagreements: doing so would reinforce errors.
- Advanced production learning: independently labeled holdout set; balanced per-class drift evaluation; contextual bandit policy with reward attribution; human adjudication; canary policies; rollback; immutable audit; fairness/risk checks; shadow evaluation; periodic offline retraining.
- Before ingesting real customer traffic: HTTPS, source authentication, validation, PII/body scrubbing, retention policy, encrypted storage, rate limiting, backpressure, and tenancy isolation. For high volume, use Kafka/Redpanda + workers + PostgreSQL/ClickHouse instead of the embedded SQLite collector.

## Run tests

`python3 -m unittest discover -s tests -v`
