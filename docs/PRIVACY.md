# Data privacy & deployment modes

A security platform should not hand your infrastructure map to a third party. Horus is
built so that **the most sensitive, highest-value work never requires an LLM at all** — CVE
correlation, SSVC prioritization, the posture score and continuous monitoring (Watchtower) are
deterministic. The LLM is used only for *judgment* (validating findings, drafting remediations,
writing the executive summary), and even that can be kept inside your perimeter or anonymized.

This gives four deployment postures. Pick per environment with three environment variables.

## The modes

| Mode | `LLM_ENABLED` | `LLM_BASE_URL` | `REDACTION_ENABLED` | Data leaves your network? |
|------|---------------|----------------|---------------------|---------------------------|
| **Sovereign — no-cloud** | `false` | (unused) | (unused) | **No.** Zero LLM calls. |
| **Sovereign — local model** | `true` | a local/VPC endpoint | recommended `true` | **No.** The model runs in your network. |
| **Private — cloud + redaction** | `true` | a cloud endpoint | `true` (default) | Yes, but hostnames/IPs/emails are pseudonymized first. |
| **Standard — cloud** | `true` | a cloud endpoint | `false` | Yes, in clear. Highest model fidelity. |

The active mode is shown in the app under **Settings → Data privacy**, and exposed at
`GET /api/privacy` (host only — the API key is never returned).

### Sovereign — no-cloud (`LLM_ENABLED=false`)

The whole pipeline runs with **zero LLM calls**. Findings are classified from the scanner output by
rules, validation uses only the deterministic gate + your team's verdict memory (no debate),
remediation drafting is skipped, and the report is templated. You still get: detected services →
CVE correlation (CISA KEV + EPSS), SSVC priority per finding, the posture timeline, Watchtower
continuous monitoring, and the board PDF. For air-gapped / classified environments.

```bash
LLM_ENABLED=false
```

### Sovereign — local model (bring your own model in your VPC)

Run an open-weight model yourself and point the app at it. The LLM agents work in full (validation
debate, remediation, richer reports) and **no data leaves your network**. Any OpenAI-compatible
endpoint works — [Ollama](https://ollama.com), [vLLM](https://github.com/vllm-project/vllm), TGI.

```bash
# Example: Ollama on the same host
LLM_ENABLED=true
LLM_BASE_URL=http://localhost:11434/v1
LLM_API_KEY=ollama                 # any non-empty string; Ollama ignores it
LLM_DEFAULT_MODEL=llama3.1:70b
REDACTION_ENABLED=true             # belt-and-suspenders; harmless when local
```

```bash
# Example: vLLM serving an OpenAI-compatible API in your cluster
LLM_BASE_URL=http://llm.internal:8000/v1
LLM_DEFAULT_MODEL=Qwen/Qwen2.5-72B-Instruct
```

An endpoint on `localhost`, an RFC1918 address (`10.x`, `192.168.x`, `172.16–31.x`), or a
`*.internal` / `*.local` host is auto-detected as in-perimeter and reported as **Sovereign**.

### Private — cloud + redaction (default)

Use a frontier cloud model for best judgment, but pseudonymize identifiers before any prompt leaves
the process. Hostnames, IPs and emails are replaced with stable placeholders (`[HOST_1]`, `[IP_1]`,
…) and restored in the response, so the model reasons over structure (products, versions, CVEs,
severities) but **never sees your names in clear**. Public reference domains (nvd.nist.gov,
mitre.org…) are kept so CVE links keep working.

```bash
LLM_ENABLED=true
LLM_BASE_URL=https://openrouter.ai/api/v1
LLM_API_KEY=sk-or-...
REDACTION_ENABLED=true
```

### Standard — cloud (no redaction)

```bash
REDACTION_ENABLED=false
```

## Honest limitations

- **Redaction is pseudonymization, not encryption.** It shrinks the blast radius; it does not remove
  the need to trust the provider with the (anonymized) prompt. For a cryptographic guarantee, use a
  local model (Sovereign) — or, on the roadmap, a confidential-computing (TEE) endpoint where the
  provider cannot see plaintext even in memory.
- Redaction seeds the asset host/name and auto-detects IPs/emails/FQDNs. An internal identifier that
  is neither seeded nor pattern-matched could slip through; Sovereign modes remove this risk entirely.
- Open-weight local models are strong but generally a step behind frontier models on nuanced
  judgment (the validation debate, remediation phrasing). The deterministic core is identical in all
  modes.

## Roadmap

- **Confidential computing (TEE):** frontier model in a hardware enclave (Intel TDX / AMD SEV-SNP /
  NVIDIA H100 Confidential Computing) with remote attestation — SOTA quality with a cryptographic
  guarantee the provider never sees plaintext.
- **Federated verdict intelligence:** cross-customer false-positive and exploitation signals shared
  in aggregate (never raw data), so the whole fleet gets smarter while each tenant's data stays put.
