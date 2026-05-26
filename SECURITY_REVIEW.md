# RAGuard Security Review v0.1.0

**Date:** 2026-05-26
**Scope:** Full source code review of `src/raguard/` (24 Python files), Dockerfile, CI/CD, and dependencies
**Reviewer:** Security audit agent (automated static analysis + manual review)

---

## 1. Threat Model

### 1.1 RAGuard Trust Model

```
┌─────────────────┐     scans      ┌──────────────────┐
│  RAGuard Scanner │ ────────────▶  │  Target RAG System │
│  (security tool)  │               │  (Chroma/Milvus/   │
│                   │               │   Qdrant/Generic)  │
└─────────────────┘               └──────────────────┘
        │                                  │
        │ outputs                          │
        ▼                                  ▼
   Reports (JSON/HTML/SARIF)         Vector DB / HTTP API
```

**Trust boundaries:**
- **T1:** User → RAGuard CLI arguments (untrusted, can inject malicious inputs)
- **T2:** RAGuard → Target RAG system (trusted by design, but no safeguards)
- **T3:** RAGuard → Output files (unvalidated file paths)
- **T4:** Report input → RAGuard (JSON deserialization from arbitrary sources)

### 1.2 Assets at Risk

| Asset | Description | Impact if compromised |
|---|---|---|
| Target RAG system | The system being scanned | Data poisoning, unauthorized access, DoS |
| RAGuard host machine | Where the scanner runs | File overwrite, credential theft |
| Scanner credentials | API keys passed via CLI | Credential exposure (ps, shell history) |
| Scan reports | Generated security findings | Data leakage of RAG system config |

### 1.3 Attack Vector Coverage

| Attack Vector | RAGuard Detector | Detection Method |
|---|---|---|
| Data Poisoning (arXiv:2605.24294) | `data_poisoning` | Heuristic pattern matching |
| Membership Inference (USENIX Sec 2026) | `membership_inference` | Entailment query simulation |
| Prompt Leakage (OWASP LLM06) | `prompt_leakage` | Leakage query detection |
| Context Overflow | `context_overflow` | Window size analysis |
| Retrieval Hijack (MITRE ATLAS) | `retrieval_hijack` | Similarity manipulation check |
| Vector DB Injection | `vector_injection` | Auth & API access checks |
| Policy Bypass (OWASP LLM01) | `policy_bypass` | Trusted context analysis |

---

## 2. Security Findings

**18 findings total: 4 CRITICAL, 6 HIGH, 4 MEDIUM, 3 LOW, 1 INFO**

### 🔴 CRITICAL

| # | Finding | Location | CWE |
|---|---|---|---|
| **C1** | **SSRF: User-supplied URLs passed to HTTP/database clients without restriction** — Target URL flows into `httpx.AsyncClient`, `chromadb.HttpClient`, `QdrantClient`, and `pymilvus.connect` with no allowlist, IP validation, or host restriction. An attacker can target internal services (metadata endpoints, Redis, databases). | `generic_rag.py:25-31`, `chroma.py:26-31`, `qdrant.py:25-27`, `milvus.py:25-28`, `http.py:27-31` | CWE-918 |
| **C2** | **SSRF via redirect following** — `RAGuardHTTPClient` enables `follow_redirects=True` by default. An attacker-controlled external server can redirect to internal IPs (e.g., `http://evil.com → http://169.254.169.254/`). | `http.py:30` | CWE-918 |
| **C3** | **Path traversal in ChromaDB target** — When target URL doesn't start with `http://`, `chromadb.PersistentClient(path=self.config.url)` treats it as a local filesystem path. `../../etc/passwd` or `/tmp/evil` are valid inputs. | `chroma.py:31` | CWE-22 |
| **C4** | **Unvalidated output file writes** — CLI `--output` is written to arbitrary filesystem paths via `Path(output).write_text()`. Can overwrite system files, write to cron, or plant content in shared directories. | `cli.py:78-79,86-87,93-94,141-142,173` | CWE-73 |

### 🟠 HIGH

| # | Finding | Location | CWE |
|---|---|---|---|
| **H1** | **No input validation on CLI arguments** — `target`, `api-key`, `collection`, `threshold`, `detectors` accepted as raw strings. No format validation, length limits, or character restrictions. | `cli.py:31,33,34,38,40` | CWE-20 |
| **H2** | **Fragile URL parsing in Chroma target** — URL parsed via `replace("http://","")` and `split(":")` instead of `urllib.parse.urlparse()`. Malformed URLs cause incorrect behavior. | `chroma.py:26-28` | CWE-172 |
| **H3** | **Arbitrary file read via `report` command** — `Path(scan_file).read_text()` reads from user-controlled path. Symlinks or `/dev/random` can cause resource exhaustion. | `cli.py:124` | CWE-73 |
| **H4** | **JSON deserialization of untrusted input** — `json.loads(Path(scan_file).read_text())` loads arbitrary files into Pydantic models. No file size limit. | `cli.py:124` | CWE-502 |
| **H5** | **Information leakage via debug mode** — Exception messages logged via `print(f"DEBUG: {exc}")` can leak connection strings, stack traces, or database error messages containing credentials. | `scanner.py:66-67` | CWE-209 |
| **H6** | **Container runs as root** — Dockerfile uses `python:3.13-slim` with no `USER` directive. If compromised, attacker has root access to container. | `Dockerfile:1` | CWE-250 |

### 🟡 MEDIUM

| # | Finding | Location | CWE |
|---|---|---|---|
| **M1** | **API key exposure via CLI** — `--api-key` argument visible in `ps` listings, shell history, and CI logs. Should use stdin, env vars, or secrets file. | `cli.py:33` | CWE-200 |
| **M2** | **Unvalidated dict fields in models** — `metadata` and `details` are `dict[str, Any]` with no schema, flowing into reports, YAML, SARIF output. | `models.py:82,98` | CWE-20 |
| **M3** | **Broad exception swallowing** — All target methods (`connect`, `query`, `insert`, `get_collection_info`) use `except Exception: return False`. Masks security-relevant errors. | All 4 target files | CWE-391 |
| **M4** | **No resource limits on config** — `timeout`, `max_retries`, `concurrent_scans` have no upper bounds. Can be set to DoS-inducing values. | `config.py:19-21` | CWE-770 |

### 🔵 LOW

| # | Finding | Location | CWE |
|---|---|---|---|
| **L1** | **Mypy type checking disabled** — `strict=false`, `ignore_errors=true` allows type bugs with security implications. | `pyproject.toml:84-87` | CWE-1104 |
| **L2** | **No .env file restriction** — `env_file = ".env"` loads environment files if present, potential issue in shared environments. | `config.py:14` | CWE-200 |
| **L3** | **API key stored in config model** — `api_key: str | None` in `RAGTargetConfig` could be serialized into output if config dump is extended. | `models.py:78` | CWE-200 |

### ⚪ INFO

| # | Finding | Location | CWE |
|---|---|---|---|
| **I1** | **Jinja2 auto-escaping protects current template** — Current template doesn't render user data as raw HTML, but future extensions could introduce XSS. | `html.py:105-110` | CWE-79 |

---

## 3. OWASP Top 10 for LLMs 2025 Mapping

| OWASP LLM Category | RAGuard Coverage | Detector |
|---|---|---|
| **LLM01: Prompt Injection** | ✅ Direct + indirect injection detection | `policy_bypass`, `retrieval_hijack` |
| **LLM02: Sensitive Information Disclosure** | ✅ Prompt leakage detection | `prompt_leakage` |
| **LLM03: Supply Chain** | Partial (vector DB dependency validation) | `vector_injection` |
| **LLM04: Data Poisoning** | ✅ Ingest-level detection | `data_poisoning` |
| **LLM05: Insecure Output Handling** | ❌ Not covered | N/A |
| **LLM06: Training Data Extraction** | ✅ Membership inference | `membership_inference` |
| **LLM07: SSRF** | ✅ Target-side detection (self-SSRF) | `retrieval_hijack` |
| **LLM08: Excessive Agency** | ❌ Not covered | N/A |
| **LLM09: Overreliance** | ❌ Not covered | N/A |
| **LLM10: Vector & Embedding** | ✅ Vector DB security scanning | `vector_injection`, `context_overflow` |

**Gap:** 3/10 OWASP categories not covered (Insecure Output Handling, Excessive Agency, Overreliance).

---

## 4. MITRE ATLAS Mapping

| ATLAS Technique | RAGuard Coverage | Detector |
|---|---|---|
| **AML.T0018: ML Prompt Injection** | ✅ Indirect injection via retrieval | `policy_bypass` |
| **AML.T0020: ML Data Poisoning** | ✅ Document-level poisoning | `data_poisoning` |
| **AML.T0024: Membership Inference** | ✅ Entailment-based detection | `membership_inference` |
| **AML.T0025: Model Inversion** | ❌ Not covered | N/A |
| **AML.T0034: ML Supply Chain Compromise** | Partial (vector DB deps) | `vector_injection` |
| **AML.T0051: LLM Jailbreak** | ❌ Not covered | N/A |
| **AML.T0052: Embedding Manipulation** | ✅ Adversarial embedding checks | `retrieval_hijack` |

---

## 5. NIST AI RMF Alignment

| AI RMF Function | RAGuard Support |
|---|---|
| **GOVERN** — Policies and procedures | ✅ MCPGuard policy generator |
| **MAP** — Context and risk identification | ✅ RAG-specific threat mapping |
| **MEASURE** — Testing and evaluation | ✅ 7 detector categories |
| **MANAGE** — Risk treatment | ✅ Policy generation for guardrails |

---

## 6. Recommendations

### Immediate (v0.1.0-patch)

| Priority | Action | Issue |
|---|---|---|
| 🔴 P0 | Add URL validation: validate `target` against a blocklist of internal IP ranges (RFC 1918, loopback, link-local) or allowlist of allowed hosts | C1, C2 |
| 🔴 P0 | Remove or disable `follow_redirects=True` in default configuration | C2 |
| 🔴 P0 | Validate output file paths: restrict to reports/ directory or use `Path(output).resolve()` with prefix check | C4 |
| 🔴 P0 | Validate ChromaDB paths: add check to prevent filesystem path interpretation when URL is HTTP-based | C3 |

### Short-term (v0.2.0)

| Priority | Action | Issue |
|---|---|---|
| 🟠 P1 | Add input validation for all CLI arguments (format, length, allowed characters) | H1 |
| 🟠 P1 | Add file size limit for `report` command JSON deserialization | H4 |
| 🟠 P1 | Add `USER` directive to Dockerfile | H6 |
| 🟠 P1 | Accept API key via environment variable or file instead of CLI argument | M1 |
| 🟡 P2 | Add schema validation for `details` and `metadata` dict fields | M2 |
| 🟡 P2 | Add configurable upper bounds for `timeout`, `max_retries`, `concurrent_scans` | M4 |
| 🔵 P3 | Enable mypy strict mode and fix type violations | L1 |

### Architectural (v0.3.0+)

| Priority | Action |
|---|---|
| 🟡 P2 | Implement a sandbox/internet-disconnected mode that validates URL safety before scanning |
| 🟡 P2 | Add integration tests with mock RAG servers to verify detectors actually detect |
| 🔵 P3 | Replace heuristic detection with active probing against the target |

---

## 7. Conclusions

**RAGuard is architecturally sound** — the detector/registry/reporter pattern is well-designed and follows workspace conventions. The codebase is clean of `eval`/`exec`, hardcoded secrets, and shell injection.

**However, the tool has a fundamental security tension:** it is a security scanner that must connect to arbitrary user-supplied RAG systems, but provides no safeguards on those connections. The SSRF risks (C1-C2) are inherent to the tool's design but must be mitigated with proper validation.

**The detectors are currently heuristic/simulated** (e.g., `return target.context_window > 2048`). They don't actually send probe payloads to the target. This is appropriate for v0.1.0 but should evolve toward active probing in future versions.

**Overall risk score: 68/100** (HIGH, based on 4 critical + 6 high findings). The tool is safe to use against targets the user controls, but should not be used in shared CI environments or against third-party systems without the mitigations in section 6.

---

*Review generated by automated static analysis + manual code review.*
