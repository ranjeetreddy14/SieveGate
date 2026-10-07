# SieveGate

**A zero-trust gate that screens every prompt before it leaves for an LLM, and recommends the cheapest model that can handle it.**

![SieveGate demo summary: 15 scenes, their decisions and where they were decided](docs/demo/summary.svg)

**[See the 5-minute demo walkthrough →](docs/DEMO.md)** It runs locally with no API key: `python demo/run_demo.py`.

## Why it exists

People paste whatever they're working on into AI tools: stack traces with database passwords, customer records, private keys, patient notes. Once a prompt reaches a third-party LLM API, the data has left your control. Meanwhile, many teams send every request to their largest, most expensive model, even simple ones a small model would handle well.

## How it works

```mermaid
flowchart LR
    A[Caller payload] --> B{Text?}
    B -- no --> X1[BLOCKED: modality]
    B -- yes --> C[Local pre-filter<br/>stdlib regex + checksums<br/>no network]
    C -- finding --> X2[BLOCKED: prefilter<br/>payload never left the machine]
    C -- no findings --> D[Jev classifier<br/>TypeSafe API]
    D -- timeout / error --> X3[BLOCKED: fail-secure]
    D -- verdict --> E[EnforcementPolicy]
    E -- rule hit --> X4[BLOCKED: policy]
    E -- confirm category --> OK2[PASS + reconfirm]
    E -- clean --> OK1[PASS + routing tier]
```

1. A **local pre-filter** catches known secret formats, card numbers, SSNs and IBANs on your machine. A blocked payload never leaves.
2. Everything else gets **one call** to a fast structured-decision model (TypeSafe's Jev), which answers six questions at once: personal data, secrets, financial records, leak risk, content category and model tier.
3. A configurable **enforcement policy** turns those answers into block, pass, or "pass, but ask a person to reconfirm". The pass decision comes with a recommended model tier.

SieveGate returns a decision and doesn't make the LLM call itself. More detail: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Results

Measured on a holdout set of 300 fake payloads that were never used for tuning (Oct 6, 2026; 298 scored, of which 207 should be blocked and 91 should pass):

| Measure | Result |
|---|---|
| Dangerous payloads caught | **206 of 207** (false-pass rate 0.5%) |
| ...of which stopped locally, with no network call | **20 of 207** (9.7%; the local pre-filter, simulated offline on the same set) |
| Harmless payloads blocked (false-block rate) | **17.6%** (16 of 91): a deliberate zero-trust trade-off, mostly on lookalike traps; adjustable |
| Overall accuracy | **94.3%** |
| Latency per classifier decision | median **111 ms**, p90 **143 ms** |

These figures measure the classifier and policy. With the local pre-filter added (simulated on the same set), accuracy is 93.6% and the false-block rate 19.8%. The pre-filter adds two blocks, both well-known example values (a published test card number and a publicised example SSN), which are blocked by design. The full numbers, what was accepted and why, and how they were measured are in [DEMO.md section 5](docs/DEMO.md#5-the-numbers-honestly).

## Quickstart

**Run the demo** (no key, no network):

```
pip install -e .[demo]
python demo/run_demo.py
```

**Put the gate in front of your LLM call:**

```python
from sievegate.sieve import SieveGate

gate = SieveGate(classifier)   # any Classifier implementation (see below)

async def ask_llm(prompt: str) -> str:
    result = await gate.evaluate_payload(prompt)
    if result.routing.tier.value == "blocked":
        return f"Not sent: {result.routing.reason}"           # reason codes only, never payload text
    if result.needs_confirmation and not await confirm_with_user(result.confirm_reasons):
        return "Not sent: the user didn't confirm"
    return await call_your_llm(prompt, tier=result.routing.tier.value)  # small / medium / large
```

`classifier` is any implementation of the `Classifier` interface: the commercial edition includes the adapter for TypeSafe's Jev model, and `MockClassifier` lets you try the gate without one. `confirm_with_user` and `call_your_llm` are your own code. Configuration is covered in [Local pre-filter](#local-pre-filter), [Enforcement policy](#enforcement-policy) and [Reconfirmation](#reconfirmation-pass-but-ask-a-person-first) below.

## Design principles

- **Fail-secure.** No answer in time, an error or malformed output from the classifier means BLOCKED. One timeout, one blocked path.
- **Vendor-swappable classifier.** The gate depends on an abstract `Classifier` interface, and the policy reads only vendor-neutral signals, so Jev can be replaced.
- **No payload text in logs.** Results carry reason codes and exception type names only, and the Jev adapter stops the vendor SDK from logging request bodies at DEBUG level.
- **The pre-filter can only tighten the gate.** It blocks or defers to the classifier, and never marks a payload as safe.
- **Frozen, auditable results.** Every decision is an immutable result with the reason codes of every rule that fired.

## How this was built

Ranjeet Reddy Manchana designed SieveGate: the architecture, the security model (zero-trust defaults, fail-secure handling, local pre-filtering), the evaluation method, and every product and policy decision. Claude, Anthropic's AI model, was used to build the project, implementing each phase from written design blueprints. Every phase was verified with offline tests (333 in this edition's suite) and with blind payload sets: thresholds were tuned on development sets, then measured once on a holdout set that was never used for tuning. Each decision and the reasoning behind it is recorded in the project's internal decision log.

## Licensing

**All rights reserved; the public source is view only.** You may read the code and run the demo and tests to evaluate SieveGate. You may not copy, modify, redistribute or reuse it without written permission. A commercial edition is planned as a one-time site license (a plain Python wheel, documentation and a contract, provided as-is, with no hosted service). Its terms are a draft and not yet offered for sale. See [LICENSING.md](LICENSING.md).

---

*The sections below are the detailed reference.*

## Local pre-filter

Before anything is sent to the classifier, SieveGate runs a fast, offline pattern check on the payload. If it finds something, the payload is blocked **and never leaves your machine**. It uses only the Python standard library and makes no network calls.

The pre-filter can only make the gate stricter. A scan returns findings (block) or no findings (carry on to the classifier as usual). It never marks a payload as safe or lets it skip the classifier.

### What it catches

| Detector ID | Kind (in reason codes) | What it matches |
|---|---|---|
| `pem_private_key` | `private_key` | A PEM private-key header (PKCS#8, encrypted PKCS#8, RSA, EC, DSA, OpenSSH, PGP). Public keys and certificates don't match. |
| `aws_access_key_id` | `cloud_credential` | AWS access key IDs (`AKIA…` long-term, `ASIA…` temporary). |
| `github_token` | `code_host_token` | GitHub tokens (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`, `github_pat_`). |
| `slack_token` | `chat_token` | Slack bot, user and app-level tokens (`xoxb-`, `xoxp-`, `xapp-` and older `xox` forms). |
| `stripe_live_key` | `payment_credential` | Stripe live secret and restricted keys (`sk_live_`, `rk_live_`). |
| `google_api_key` | `cloud_credential` | Google API keys (`AIza` + 35 characters). |
| `llm_api_key` | `ai_credential` | Anthropic (`sk-ant-api03-`, `sk-ant-admin01-`) and OpenAI keys (identified by the marker every OpenAI key contains). |
| `jwt` | `bearer_token` | JSON Web Tokens, confirmed by decoding the header and payload. |
| `credentialed_url` | `credentialed_url` | URLs with a password in them (`scheme://user:password@host`), unless the password is an obvious placeholder such as `password`, `changeme`, `<password>`, `${DB_PASS}` or `****`. |
| `payment_card` | `card_number` | Card numbers, confirmed by the Luhn checksum and a known issuer prefix and length (Visa, Mastercard, Amex, Discover). Published test card numbers count as cards. |
| `us_ssn` | `national_id` | US Social Security numbers written with dashes or spaces, if valid under SSA rules (so the `000-00-0000` placeholder is ignored). |
| `iban` | `bank_account` | IBANs, compact or in groups of 4, confirmed by the ISO 13616 mod-97 check. |

**Deliberately left to the classifier:** `password = …` assignments and random-looking strings, email addresses, phone numbers, names, addresses, dates of birth, health, HR and legal content, Stripe test-mode keys, and encoded or obfuscated secrets. Pattern-matching these is either too noisy or needs an understanding of context. The pre-filter also does no Unicode normalisation, so full-width or look-alike-character variants are left to the classifier too.

### What a pre-filter block looks like

```python
result = await gate.evaluate_payload("Customer SSN 078-05-1120, please summarise")
result.routing.tier          # ModelTier.BLOCKED
result.routing.reason        # "blocked by prefilter: prefilter:national_id"
result.prefilter_findings    # (Finding(kind='national_id', detector='us_ssn', start=13, end=24),)
result.error                 # None: a decision, not an error
result.policy_reasons        # (): the classifier and the policy never ran
```

A finding holds the kind, the detector ID and the span. **It never holds the matched text.** If the pre-filter itself fails (an exception, or a custom detector returning a bad span), the payload is blocked fail-secure with `error == "prefilter error: <ExceptionType>"`.

### Modes

Set the mode with `SieveGateSettings(prefilter_mode=...)`:

| Mode | Behaviour |
|---|---|
| `"enforce"` (default) | Any finding blocks. The classifier is not called. |
| `"observe"` | Findings are recorded in `result.prefilter_findings`, but the payload carries on to the classifier and the policy decides. **Observe mode sends the payload, secrets included, to the classifier (TypeSafe).** Use it only to measure the pre-filter on traffic you are allowed to send. |
| `"off"` | The pre-filter doesn't run. Payloads go straight from the modality checks to the classifier. |

Non-text and empty payloads are still blocked first, before the pre-filter runs.

### Turning a detector off, or adding your own

```python
from sievegate.prefilter import PreFilter, RegexDetector
from sievegate.sieve import SieveGate, SieveGateSettings

prefilter = PreFilter(
    disabled_detectors={"iban"},   # IDs from the table above; unknown IDs raise
    extra_detectors=(
        RegexDetector("project_codename", "internal_codename", r"\bPROJECT-ORION\b"),
    ),
)
gate = SieveGate(classifier, SieveGateSettings(prefilter_mode="enforce"), prefilter=prefilter)
```

A custom detector is a `RegexDetector`, or any subclass of `sievegate.prefilter.Detector` with an `id`, a `kind` and a `find(text)` method that yields `(start, end)` spans. IDs and kinds are limited to letters, digits, `_`, `.` and `-`, because they appear in reason codes. A bad configuration raises when the `PreFilter` is built.

### Redacting locally and resending

The spans are exposed on purpose. You already hold the payload, so they reveal nothing new, and they let you redact on your own machine and try again. `redact()` replaces each span with `[REDACTED:<kind>]` and merges overlapping findings:

```python
from sievegate.prefilter import redact

result = await gate.evaluate_payload(prompt)
if result.prefilter_findings:
    redacted = redact(prompt, result.prefilter_findings)
    # "Customer SSN [REDACTED:national_id], please summarise"
    result = await gate.evaluate_payload(redacted)   # goes through the full gate again
```

The redacted text still goes through the full gate, classifier included, so whether it is sent is decided as usual.

## Enforcement policy

After the pre-filter, every payload goes through two stages.

1. **Fail-secure checks** always come first and always block, whatever the policy says: non-text or empty payloads, classifier errors, classifier timeouts, and malformed classifier output (including any signal outside 0–1). These results have `error` set.
2. **The enforcement policy** then checks the classifier's verdict. Every rule is evaluated, not just the first one to fire, and each one that fires adds a short reason code to `result.policy_reasons`.

### Defaults (zero-trust)

`SieveGate(classifier)` uses `EnforcementPolicy()`, which blocks if **any** of these hold:

| Setting | Default | Blocks when | What it catches |
|---|---|---|---|
| `pii_threshold` | `0.30` | `pii_probability >= 0.30` | Personal data. Set low on purpose, so borderline cases are caught. |
| `secret_threshold` | `0.50` | `secret_probability >= 0.50` | Credentials and other secrets. |
| `financial_threshold` | `0.50` | `financial_probability >= 0.50` | Sensitive financial data. |
| `max_leak_risk` | `0.50` | `data_leak_risk >= 0.50` | A high leak-risk score (level 2 or above on the classifier's 0–4 scale). |
| `min_leak_confidence` | `0.30` | leak-risk confidence `< 0.30` | Cases where the classifier can't make up its mind about the risk. Unsure means block. |
| `block_categories` | `credentials`, `customer_pii`, `employee_hr`, `health_records`, `legal_contract`, `infrastructure_security` | the content category is in the set | Content whose category label is one of these six. `financial_records` and `strategy_confidential` are opt-in (see below). |
| `confirm_categories` | `financial_records` | the content category is in the set (and nothing blocks) | Doesn't block. The payload passes with `needs_confirmation=True`, so a person can reconfirm it. See "Reconfirmation" below. |
| `block_on_missing_signal` | `True` | a signal an active rule needs is missing | A classifier that didn't provide a signal can't be assumed safe. |
| `mode` | `"enforce"` | (see observe mode) | |
| `extra_rules` | `()` | a rule of yours returns a reason code | Your own policy, e.g. a model-tier cap (see below). |

> **How these defaults were chosen.** The thresholds were tuned on a blind test set of 70 fake payloads and the blocking categories on a second set of 259. On a 300-payload holdout set they were never tuned on, they caught 206 of 207 dangerous payloads but blocked 17.6% of harmless ones, missing the 10% target. This was accepted as a zero-trust trade-off (see [DEMO.md section 5](docs/DEMO.md#5-the-numbers-honestly)). Measure them on your own traffic before relying on them, and loosen them as below if your false-block budget is tighter.

The category rule is there because the probability rules alone missed sensitive documents that aren't obviously "personal data", such as medical notes, legal agreements and HR memos. On the 259-payload test set the classifier labelled 15 of those 16 misses correctly, and blocking on the six default labels cut the misses from 16 to 3 for one extra false block. `financial_records` doesn't block by label, because finance text is often hypothetical. Instead it asks for reconfirmation (see below), and clearly sensitive financial data is still blocked by the financial probability rule. `strategy_confidential` is opt-in: adding it changed nothing on that set.

### Reconfirmation: pass, but ask a person first

Some content is often harmless but sometimes isn't. Finance text is the main case: much of it is harmless to send, but some isn't. For labels in `confirm_categories` (by default `financial_records`), the gate doesn't block. It lets the payload through with:

- `result.needs_confirmation == True`
- `result.confirm_reasons`, e.g. `("confirm:category:financial_records",)`

SieveGate doesn't make the LLM call, so it can't ask anyone itself. **Your code should ask the user to reconfirm before sending** when `needs_confirmation` is true:

```python
result = await gate.evaluate_payload(prompt)
if result.routing.tier.value == "blocked":
    ...  # don't send
elif result.needs_confirmation:
    ...  # ask the user "this looks like financial records, send anyway?" and send only on yes
else:
    ...  # send
```

Truly sensitive financial data is still **blocked**, not just flagged. Clearly sensitive financial data pushes `financial_probability` over `financial_threshold`, and a block always wins over a request to reconfirm. A result that is blocked never has `needs_confirmation` set, though `confirm_reasons` is kept for the audit trail. A label in both `block_categories` and `confirm_categories` blocks. Set `confirm_categories=frozenset()` to turn reconfirmation off. Code that ignores `needs_confirmation` behaves exactly as before: those payloads simply pass.

### Display flags are informational

`result.verdict.contains_pii`, `contains_secret` and `contains_financial` are yes/no flags for display and logging. The classifier sets them at its own cut-off (0.5 for the TypeSafe classifier). **They don't decide blocking.** The policy reads the underlying probabilities (`pii_probability` and the others) and applies its own thresholds. With the defaults, a payload with personal-data probability 0.40 is blocked for `pii>=0.30` while `contains_pii` reads `False`. To know why a payload was blocked, read `result.policy_reasons`, not the flags.

### Reason codes

| Code | Meaning |
|---|---|
| `pii>=0.30`, `secret>=0.50`, `financial>=0.50`, `leak>=0.50` | That signal reached its threshold (the number shown is your threshold). |
| `leak_conf<0.30` | The leak-risk confidence was below the minimum. |
| `category:<label>` | The content category is one you block. |
| `missing:<field>` | The classifier didn't provide a signal an active rule needs. |
| `rule:<name>:<code>` | Your extra rule `<name>` returned `<code>`. |
| `rule_error:<name>` | Your extra rule raised, or returned something other than `None` or a non-empty string. |

Codes never contain payload text. In enforce mode a blocked result has `routing.tier == ModelTier.BLOCKED` and `routing.reason == "blocked by policy: <codes joined by ;>"`. The classifier's verdict and raw answers are kept, so you can log why.

### Loosening or tightening the policy

Build your own `EnforcementPolicy` and pass it to the gate. Invalid settings (an unknown mode, a threshold outside 0–1, an unknown category label) raise immediately rather than failing quietly later.

```python
from sievegate.policy import EnforcementPolicy
from sievegate.sieve import SieveGate

policy = EnforcementPolicy(
    pii_threshold=0.5,           # flag fewer borderline personal-data cases
    min_leak_confidence=None,    # None turns a rule off entirely
    block_categories={"credentials", "health_records", "financial_records"},  # choose your own labels
)
gate = SieveGate(classifier, policy=policy)
```

Content category labels: `general_text`, `source_code`, `credentials`, `customer_pii`, `employee_hr`, `financial_records`, `health_records`, `legal_contract`, `strategy_confidential`, `infrastructure_security`.

If you use another classifier that doesn't provide some signals, either turn the rules that need them off (set them to `None`) or set `block_on_missing_signal=False`. Otherwise every payload is blocked with `missing:<field>`.

### Observe mode for trial rollouts

```python
gate = SieveGate(classifier, policy=EnforcementPolicy(mode="observe"))
result = await gate.evaluate_payload(prompt)
if result.would_block:
    log.info("would have blocked: %s", ";".join(result.policy_reasons))
```

In observe mode the policy runs in full, but its hits don't block: the result keeps the classifier's recommended tier, with `would_block=True` and the reason codes attached. Use this to measure false blocks on real traffic before switching to `"enforce"`. **Fail-secure checks still block in observe mode.** `result.policy_mode` records which mode produced the result.

### Your own rules, and the `context` hook

`evaluate_payload(payload, context=None)` takes an optional `context` mapping, which is handed to your extra rules. An extra rule is a plain (not `async`) callable:

```python
def my_rule(result, context) -> str | None:
    ...  # return a short reason code to block, or None to allow
```

- `result` is the classifier's `ClassificationResult` (verdict, routing recommendation, raw answers).
- `context` is whatever you passed to `evaluate_payload`, or `None`.
- A rule that raises blocks the payload with `rule_error:<name>`. The exception message is never recorded.
- SieveGate never logs `context` or copies it into the result. **Your returned code must not contain payload or context text**: keep it to a fixed short string.

### Example (not shipped): a model-tier cap

Model-tier routing is **advisory**: SieveGate recommends a tier and never enforces it. **Tier enforcement is off unless you add a rule like this one yourself.** It isn't part of the library. It shows how the hook lets you build tier enforcement without changing SieveGate.

The caller passes the model it intends to use, and you supply the map from your own models to tiers. The rule blocks when the requested model is a bigger tier than SieveGate recommended:

```python
from sievegate.models import ModelTier
from sievegate.policy import EnforcementPolicy
from sievegate.sieve import SieveGate

# Your catalogue: which tier each of your models belongs to.
MODEL_TIERS = {
    "acme-mini": ModelTier.SMALL,
    "acme-standard": ModelTier.MEDIUM,
    "acme-frontier": ModelTier.LARGE,
}
_RANK = {ModelTier.SMALL: 1, ModelTier.MEDIUM: 2, ModelTier.LARGE: 3}


def tier_cap(result, context):
    requested = MODEL_TIERS.get((context or {}).get("requested_model"))
    if requested is None:
        return "unknown_model"              # fail closed on models you didn't list
    if _RANK[requested] > _RANK.get(result.routing.tier, 0):
        return "tier_over_cap"
    return None


gate = SieveGate(classifier, policy=EnforcementPolicy(extra_rules=(tier_cap,)))
result = await gate.evaluate_payload(prompt, context={"requested_model": "acme-frontier"})
# A prompt recommended for "small" comes back blocked with
# policy_reasons == ("rule:tier_cap:tier_over_cap",)
```

Because SieveGate only returns decisions, "enforcement" here means your code honours the block. A gentler variant could leave the payload unblocked and have your code downgrade the request to the recommended tier instead.

---

Copyright © 2026 Ranjeet Reddy Manchana. All rights reserved. See [LICENSING.md](LICENSING.md).
