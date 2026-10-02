# Security & Privacy

This project analyses hostile input by design. That makes its own safety
properties part of the deliverable, not an afterthought.

---

## 1. The three hard guarantees

These are enforced by tests, not by convention. Each one fails the suite if
violated.

### 1.1 No URL is ever opened

URL analysis is **static string analysis**. The application never opens a
connection, never resolves a hostname, never follows a redirect.

```python
# tests/test_detection.py
def test_safety_url_analysis_makes_no_network_call(monkeypatch):
    def _boom(*a, **k):
        raise AssertionError("network access attempted during URL analysis")
    monkeypatch.setattr(socket.socket, "connect", _boom)
    monkeypatch.setattr(socket, "create_connection", _boom)
    monkeypatch.setattr(socket, "gethostbyname", _boom)
    analyze_url("http://198.51.100.10/verify-account")   # must not raise
```

**Why it matters.** Fetching a phishing URL confirms the address is live,
leaks the analyst's IP, and can trigger a drive-by payload. Analysis tools that
"just check" the link have caused real incidents.

### 1.2 No attachment is ever read

Attachment analysis uses the **filename and extension only**.

```python
def test_safety_attachment_analysis_never_touches_the_filesystem(monkeypatch):
    monkeypatch.setattr(builtins, "open", _boom)
    analyze_attachment("invoice.pdf.exe")                # must not raise
```

### 1.3 The email body is not stored by default

`STORE_EMAIL_BODY=false`. Only a short preview and the sender's **domain** are
persisted — never the full address.

```python
def test_22c_email_body_is_not_persisted(temp_db):
    marker = "ZZUNIQUEBODYMARKER42"
    client.post("/api/analyze", json={... "body": f"...{marker}..."})
    raw = pathlib.Path(temp_db).read_bytes()
    assert marker.encode() not in raw    # greps the entire SQLite file
```

**Why it matters.** A reported phishing email often contains the victim's own
data — names, invoice numbers, internal references. An analysis tool that
silently archives every body becomes a data-protection liability, and a juicy
target.

---

## 2. Defanging

Every URL is neutralised before it leaves the analyzer:

```
http://198.51.100.10/verify-account   →   hxxp://198[.]51[.]100[.]10/verify-account
```

Defanging happens **inside the URL analyzer**, so the API, the database and the
browser only ever handle the safe representation. There is no code path that
renders a clickable attacker URL, and no email client or chat app will
auto-link it when the report is pasted elsewhere.

---

## 3. Application security

| Risk | Control |
|---|---|
| **SQL injection** | Every query is parameterised. `sort_by` is validated against a whitelist — an unknown column returns **422**, never reaches SQL. |
| **XSS** | React escapes all interpolated text. Email content is **never** rendered as HTML; `dangerouslySetInnerHTML` appears nowhere in the codebase. |
| **Input abuse** | Pydantic v2 validates every request. Length caps on subject, body and URL lists prevent memory exhaustion. |
| **Password storage** | PBKDF2-SHA256, **200,000 iterations**, 16-byte per-user salt, `hmac.compare_digest` for verification. |
| **Session tokens** | `secrets.token_urlsafe(32)`, stored hashed, with expiry. |
| **Rate limiting** | Per-client sliding window on analysis endpoints (configurable; raised to 100,000 inside the test fixture so tests don't throttle each other). |
| **Path traversal** | Uploads are parsed in memory. No user-supplied string is ever used to build a filesystem path. |
| **Error leakage** | Exception handlers return a generic message; the traceback goes to the log, not the response. |
| **Network exposure** | Uvicorn binds `127.0.0.1` by default. |
| **Secrets** | `.env` is git-ignored. `.env.example` contains no real values. No key, token or password is hard-coded anywhere. |

---

## 4. Data handling

### What is stored

| Field | Stored | Note |
|---|---|---|
| Sender **domain** | ✅ | Needed for the domain-risk chart |
| Sender full address | ❌ | Never persisted |
| Subject | ✅ | Truncated |
| Body | ❌ | Unless `STORE_EMAIL_BODY=true` |
| Body preview | ✅ | Short, truncated |
| URLs | ✅ | **Defanged only** |
| Attachment filename | ✅ | Name only; no file content |
| Scores and indicators | ✅ | The analysis output |

### Retention

There is no automatic retention policy — this is a local, single-user tool.
`DELETE /api/analyses/{id}` removes an analysis and cascades to its indicators
and URL rows (`ON DELETE CASCADE`, verified by a test that counts orphans
directly in SQLite). `python -c "from backend.models.database import reset_db; reset_db()"`
clears everything.

**If you adapt this for multi-user or organisational use, add a retention
policy before you add users.** Storing other people's reported emails
indefinitely is a compliance problem.

---

## 5. Ethical boundaries

### What this project does NOT do — by design

- ❌ Send email of any kind. There is no SMTP code in the repository.
- ❌ Collect, store or transmit credentials.
- ❌ Host, generate or template a phishing landing page.
- ❌ Scan, probe or attack any host.
- ❌ Open, resolve or follow any URL.
- ❌ Open, unpack or execute any attachment.
- ❌ Contact any external service. The application makes **no outbound network
  calls at all**.

### Synthetic data only

| Resource | Standard | Examples used |
|---|---|---|
| Domains | RFC 2606 / RFC 6761 | `example.com`, `example.org`, `example.net`, `*.invalid.test` |
| IP addresses | RFC 5737 | `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` |

No real person, company, brand, domain or IP appears in the dataset, the tests,
the awareness content or the documentation.

### The simulation templates

The awareness module includes three phishing templates. They exist so a learner
can **paste them into this analyzer** and see how the indicators fire, and for
classroom discussion. They are labelled accordingly.

**Running a phishing simulation against real people requires explicit written
authorisation from that organisation.** Without it, it may be a criminal
offence. This project does not send anything and cannot be used to.

---

## 6. Deployment warnings

This is a **local educational tool**. Before exposing it to a network:

1. **Change `SECRET_KEY`** in `.env`. The default is a development placeholder.
2. **Enable authentication.** It is optional and off by default.
3. **Put it behind HTTPS** with a reverse proxy.
4. **Restrict CORS.** Development config is permissive for the local Vite proxy.
5. **Move off SQLite** for concurrent users.
6. **Add a retention policy** before storing anyone else's mail.
7. **Re-read section 4** and decide what you are legally allowed to keep.

---

## 7. Responsible disclosure

If you find a vulnerability in this code, open an issue describing the impact
without a working exploit, or contact the repository owner privately. Please do
not test it against infrastructure you do not own.
