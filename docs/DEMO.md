# SieveGate demo walkthrough

## 1. The 60-second version

SieveGate is a Python library that sits in front of every call your code makes to an LLM API. Before a prompt leaves, it checks the prompt for secrets, personal data and other sensitive content, then either blocks it or lets it through with a recommended model tier (small, medium or large). Obvious secrets such as private keys, cloud keys, card numbers and SSNs are caught by a local check and never leave your machine. Everything else is judged by one call to a fast classifier model (TypeSafe's Jev), and a configurable policy turns its answers into a decision. If anything goes wrong, such as a timeout or an error, the prompt is blocked.

![Summary of the 15 demo scenes](demo/summary.svg)

- **20 of 207 dangerous holdout payloads (9.7%) were stopped locally**, with no network call. *Source: offline simulation of the pre-filter on the holdout set (300 payloads, Oct 6, 2026).*
- **206 of 207 dangerous holdout payloads were caught overall** (0.5% false-pass rate). *Source: holdout run, Oct 6, 2026, 300 payloads. Adding the pre-filter doesn't change this: all 20 payloads it stops were already blocked by the policy.*
- **Median 111 ms per Jev decision** (p90 143 ms). *Source: holdout run, 295 classified calls.*

## 2. Run it yourself

```
git clone <this repo>
cd SieveGate
pip install -e .[demo]
python demo/run_demo.py
```

The demo has three modes:

| Mode | Command | Needs a key? | What runs |
|---|---|---|---|
| `replay` (default) | `python demo/run_demo.py` | No, and no network | The real gate, pre-filter and policy. The classifier is replaced by `ReplayClassifier`, which returns the answers Jev gave in a live run on 2026-10-06 (`demo/recordings/live_2026-10-06.json`). |
| `prefilter-only` | `python demo/run_demo.py --mode prefilter-only` | No | Only the local checks. Scenes that would reach Jev stop with "would be sent to Jev". |
| `live` | `python demo/run_demo.py --mode live` | Commercial edition only | Real Jev calls, one per scene that gets past the local checks (8 of the 15). In this edition it says so and exits. |

Other options: `--scene <id>` runs a single scene, `--text "..."` checks your own text locally, `--policy name=value` changes a policy setting, `--record <dir>` saves one SVG screenshot per scene, and `--no-color` gives plain output.

The replay recording stores only Jev's answers, timings and a fingerprint of each payload, never the payload text. If a scene's text is edited, its fingerprint no longer matches, and the gate blocks that scene fail-secure instead of replaying a stale answer.

### Verify it yourself

You don't have to take the screenshots on trust. Each of these checks takes about a minute, and none needs an API key or a network connection.

**1. Run the tests.**

```
pip install -e ".[dev,demo]"
python -m pytest tests
```

Every test should pass. They cover the pre-filter's detectors and their lookalikes, the gate's stage order and fail-secure paths, the enforcement policy, and the demo itself. The demo tests run with networking disabled.

**2. Edit a scene and watch the gate fail secure.** Open `demo/scenes.py`, find `_plain_question`, and change any word in its text. Then run:

```
python demo/run_demo.py --scene plain_question
```

The scene now shows **BLOCKED**, decided by **fail-secure**, with the reason `classifier error: RecordingMissing` and the note "No usable recording for this scene". The edited text no longer matches the fingerprint in the recording, so the replay classifier refuses to answer, and no answer means no send. Undo your edit afterwards (with `git checkout -- demo/scenes.py`, for example).

**3. Try your own text.** `--text` runs the gate's local stages (the modality check and the pre-filter) on whatever you type. It never calls the API.

```
python demo/run_demo.py --text "Customer SSN 078-05-1120, please summarise"
python demo/run_demo.py --text "What is the capital of France?"
```

The first is **BLOCKED** by the pre-filter. The SSN is shown as `[REDACTED:national_id]`, and the output names the detector that fired (`us_ssn`). The second isn't caught locally, and the output says it "would be sent to Jev for classification". Try a password in a database URL, a private-key header or a card number from your own test data.

**4. Change a policy setting and watch the decisions change.** `--policy name=value` rebuilds the enforcement policy with that setting changed, and the gate re-decides on the same recorded Jev answers.

```
python demo/run_demo.py --scene plain_question
python demo/run_demo.py --scene plain_question --policy pii_threshold=0.05
python demo/run_demo.py --scene patient_note --policy mode=observe
```

The plain question **passes** under the default policy (personal-data signal 0.09). Lower the personal-data threshold to 0.05 and it is **BLOCKED** with `pii>=0.05`. In observe mode the patient note **passes**, but the output shows the three rules that would have blocked it. Any setting from the [policy table in the README](../README.md#defaults-zero-trust) can be changed this way, and invalid values are rejected.

## 3. How the gate decides

![The gate's four stages](demo/pipeline.svg)

The stages run in order, and the first one that says no wins:

1. **Modality check.** v1 handles text only. Images, files and empty input are blocked.
2. **Local pre-filter.** Fast pattern checks for formats that are never safe to send: private keys, cloud and API keys, credentialed URLs, card numbers (Luhn-checked), SSNs and IBANs. It runs on your machine with no network calls. A finding blocks the payload before anything is sent. The pre-filter can only add blocks; it never marks a payload as safe.
3. **Jev classifier.** One call asks six questions at once: personal data, secrets, financial records, leak risk, content category and model tier. No answer in time means BLOCKED.
4. **Enforcement policy.** Thresholds and blocked categories turn Jev's answers into a decision. Some categories, such as financial records, pass but ask a person to reconfirm first.

## 4. Scene by scene

The scene screenshots come from the live run on 2026-10-06 (typesafe-sdk 0.7.1, model `jev-latest`, default policy), and their latencies are wall-clock times from that run. Scene 13 was re-recorded later the same day, with one live call, after its text was rewritten. The summary at the top of this page is rendered in replay mode from those recordings.

### Normal traffic

#### Scene 1 · Plain question
*An employee asks a general networking question.*

![Scene 1](demo/01_plain_question.svg)

The pre-filter found nothing, so the question went to Jev. Jev labelled it `general_text` (confidence 1.00), with low personal-data, secret and financial signals and leak risk 0.05, so no rule fired. It **passed** with tier **small**, the cheapest. It left the machine, as normal traffic should. This was the first call of the run, so it was the slowest (335 ms), as usual.

#### Scene 2 · Hard reasoning
*An analyst asks a multi-step reasoning problem.*

![Scene 2](demo/02_hard_reasoning.svg)

Clean on every signal, so it **passed**. Jev recommended tier **medium** (confidence 0.74), where scene 1 got small. This is the routing half of SieveGate: a recommended model size comes with every decision.

#### Scene 3 · Code review
*A developer asks for a review of a harmless function.*

![Scene 3](demo/03_code_review.svg)

Jev labelled it `source_code` (1.00), with leak risk 0.08 and nothing sensitive in it. It **passed** with tier small. Code isn't blocked just for being code.

### Stopped locally

#### Scene 4 · Private key paste
*A developer pastes a private key into "why won't SSH work?".*

![Scene 4](demo/04_private_key_paste.svg)

The pre-filter recognised the private-key block (`prefilter:private_key`) and **blocked** it in 0.17 ms. The payload **never left the machine**: Jev was never called, so no signals are shown. In the preview, the whole key block is replaced by `[REDACTED:private_key]`.

#### Scene 5 · Cloud key in a config file
*A developer shares a config file that contains a cloud access key.*

![Scene 5](demo/05_aws_key_in_config.svg)

The access key ID matched the AWS format (`prefilter:cloud_credential`). **Blocked locally** in 0.09 ms, never sent. The preview masks only what the pre-filter found. The start of the (fake) secret key on the next line is visible, because AWS secret keys have no recognisable prefix to detect. The payload is blocked either way.

#### Scene 6 · Database password in a stack trace
*A stack trace with a credentialed database URL buried in the noise.*

![Scene 6](demo/06_db_url_with_password.svg)

The password inside the `postgres://user:password@host` URL was found among the traceback lines (`prefilter:credentialed_url`). **Blocked locally**, never sent. Placeholder passwords like `password` or `${DB_PASSWORD}` are deliberately ignored, so documentation examples don't trigger it.

#### Scene 7 · Card number in a support ticket
*A support agent pastes a ticket where the customer typed their card number.*

![Scene 7](demo/07_support_ticket_card.svg)

A 16-digit number that passes the Luhn checksum and carries a Visa prefix (`prefilter:card_number`). **Blocked locally**, never sent. Order numbers, phone numbers and Luhn-invalid digit strings don't match.

#### Scene 8 · SSN in a customer CSV row
*An analyst asks for help cleaning a CSV row that holds a customer's SSN.*

![Scene 8](demo/08_customer_row_ssn.svg)

A dash-separated number that is valid under the SSA's numbering rules (`prefilter:national_id`). **Blocked locally**, never sent.

### Caught by understanding, not patterns

#### Scene 9 · Patient note
*A clinician asks for a plain-language rewrite of a named patient's diagnosis.*

![Scene 9](demo/09_patient_note.svg)

There's no ID number or other pattern here, so the pre-filter found nothing and the note went to Jev. Jev scored personal data at 0.98 and leak risk at 0.59, and labelled it `health_records` (1.00). The policy **blocked** it on three independent rules (`pii>=0.30; leak>=0.50; category:health_records`). This is why both layers exist: the pre-filter catches formats, and Jev catches meaning.

#### Scene 10 · Performance review
*A manager drafts a named employee's performance review.*

![Scene 10](demo/10_performance_review.svg)

Jev labelled it `employee_hr` (1.00), with personal data 0.98 and leak risk 0.60. **Blocked by policy** on three rules (`pii>=0.30; leak>=0.50; category:employee_hr`). The `employee_hr` label blocks by default, even though the text contains no ID numbers.

#### Scene 11 · Base64-encoded credential
*A deploy script with a base64-encoded database credential.*

![Scene 11](demo/11_base64_secret.svg)

The encoding hides the credential from pattern matching, and the pre-filter found nothing. Jev saw through it: secret 0.90, category `credentials` (0.95), leak risk 0.88. **Blocked by policy** on three rules (`secret>=0.50; leak>=0.50; category:credentials`). The payload did go to Jev for classification, but it was not passed on to an LLM.

### Reconfirm

#### Scene 12 · Hypothetical budget
*A finance lead asks about a hypothetical department budget.*

![Scene 12](demo/12_budget_question.svg)

Jev labelled it `general_text` with low confidence (0.56; its second choice was `financial_records` at 0.30), and the financial probability was 0.09. It **passed** with tier medium.

> **Note:** this scene was written to show the "pass, but ask a person to reconfirm" outcome, which is triggered when Jev labels a payload `financial_records`. In the live run Jev chose `general_text`, so no reconfirmation was requested. We kept the real result rather than rewording the prompt to force it. This matches the holdout set, where 3 of the 4 payloads expected to trigger reconfirmation were also labelled `general_text` (all 4 still passed, which was the right gate decision). The reconfirmation rule itself is covered by the test suite.

### Edge cases and safety nets

#### Scene 13 · Placeholder SSN in a unit test
*A developer asks why a unit test using 000-00-0000 as a placeholder fails.*

![Scene 13](demo/13_placeholder_ssn_fixture.svg)

The pre-filter ignored `000-00-0000`, because it is invalid under the SSA rules (area 000), so the test went to Jev. Jev scored personal data at only 0.08, but it labelled the text `customer_pii` (confidence 0.64, with `source_code` second), and `customer_pii` blocks by default. The policy **blocked** it on that one rule (`category:customer_pii`). This is a false block: the only "customer" data is a placeholder and a sample name. It is the zero-trust trade-off described in section 5. A team that hits it often can remove `customer_pii` from `block_categories` and rely on the personal-data threshold instead.

> **Note:** an earlier version of this scene, with different test code, passed (`source_code` 0.53 against `customer_pii` 0.46). The text was rewritten before publishing, and the new result is shown exactly as it came back. Placeholder-heavy test code sits close to this category line.

#### Scene 14 · Raw image bytes
*An app sends raw image bytes to the gate.*

![Scene 14](demo/14_image_bytes.svg)

v1 screens text only, so non-text input is **blocked by modality** before any other check (0.02 ms). It never left the machine. Converting images to text is planned for a later version and will have to happen locally, because sending an image to a cloud OCR service would itself be the leak.

#### Scene 15 · Simulated classifier outage
*SIMULATED OUTAGE: the classifier never answers (the demo's timeout is shortened).*

![Scene 15](demo/15_jev_outage.svg)

For this scene the demo swaps in a classifier that never answers and shortens the gate's timeout to 0.5 s. No real API call is made. When the timeout fired, the gate **blocked** the payload fail-secure (`classifier timed out after 0.5s`). No answer means no send, in every mode. The default timeout outside the demo is 2 s.

## 5. The numbers, honestly

Measured on a **holdout set**: 300 fake payloads written for evaluation and never used for tuning, run once on Oct 6, 2026. 298 were scored (2 empty payloads only had to be handled without crashing): 207 should be blocked and 91 should pass.

| Measure | Result | Target |
|---|---|---|
| Accuracy (right block/pass decision) | **94.3%** (281 of 298) | ≥ 95% (missed) |
| False-pass rate (dangerous payload let through) | **0.5%** (1 of 207) | ≤ 3% (met) |
| False-block rate (harmless payload blocked) | **17.6%** (16 of 91) | ≤ 10% (missed) |
| p90 latency per Jev decision | **143 ms** | < 1 s (met) |

**What was accepted, and why.** The defaults are zero-trust: when in doubt, block. That kept dangerous payloads that got through to 1 in 207, at the cost of blocking 16 harmless ones. Those 16 are mostly payloads written to look dangerous on purpose: 15 are deliberate lookalike traps, 6 are examples of prompt-injection attacks, and 10 are marked borderline in the answer key. They were reviewed, and the rate was accepted as the right trade-off for a security gate.

**With the local pre-filter added** (offline simulation on the same holdout), the pre-filter stops 20 dangerous payloads locally and adds 2 false blocks: a published test card number and a widely publicised example SSN. Both kinds are blocked by design. Simulated totals: accuracy 93.6%, false-pass rate 0.5%, false-block rate 19.8%.

**Loosening the policy.** Every threshold, blocked category and pre-filter detector can be changed or turned off, and there is an observe mode for measuring a policy on real traffic before enforcing it. See [Enforcement policy](../README.md#enforcement-policy) and [Local pre-filter](../README.md#local-pre-filter) in the README.

**How it was measured.** The policy was tuned on two earlier sets (70 payloads on Sep 22, 259 on Oct 5), and results on those sets are reported separately because they are optimistic. The holdout was written afterwards and run once. Its answer key stayed outside the project folder until the run was finished, and the code never saw it. Nothing was tuned after seeing holdout results. The pre-filter's detectors were frozen before it was run on the holdout.

## 6. Limitations

- **Text only.** Images and files are blocked, not screened.
- **TypeSafe is a subprocessor** for every payload the pre-filter lets through: those payloads are sent to TypeSafe's API for classification. Only pre-filter, modality and fail-secure blocks stay entirely on your machine.
- **No Unicode normalisation in the pre-filter.** Full-width, look-alike-character or otherwise obfuscated secrets are left to Jev, which caught every obfuscation case on the holdout.
- **Routing recommendations aren't validated for cost claims.** Tier accuracy was 82.4% on the holdout, mostly routing medium tasks down to small, so no savings figures are published yet.
- **Recordings go stale.** The replay recording reflects the questions, SDK and policy as of 2026-10-06. It must be re-recorded whenever any of them changes.

## 7. Where to look in the code

- [`src/prefilter.py`](../src/prefilter.py): the local pre-filter and its detectors
- [`src/sieve.py`](../src/sieve.py): the gate, stage order and fail-secure handling
- [`src/policy.py`](../src/policy.py): the enforcement policy and reconfirmation
- [`src/classifier.py`](../src/classifier.py): the swappable classifier interface
- [`demo/replay_classifier.py`](../demo/replay_classifier.py): a second implementation of that interface, used for the replay
