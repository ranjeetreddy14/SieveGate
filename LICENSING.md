# Licensing

> **Status: commercial terms are a draft and not offered for sale pending legal review.** This page describes the planned model. It is not a contract, and nothing here grants a license. The final contract wording is still to be written and reviewed by a lawyer.

## The model

SieveGate is developed and licensed by **Ranjeet Reddy Manchana**, who holds the copyright.

SieveGate has two editions. A **public showcase edition** shows the architecture: the gate, the local pre-filter, the swappable classifier interface and the demo. It is published for viewing only (see below) and is not open source. A **commercial edition** is sold as a **one-time site license**. It includes the Python wheel, the documentation, and (once its figures are validated) a TCO worksheet for estimating model-routing savings. It is provided **as-is**: there is no hosted service, nothing to keep running on the buyer's behalf, and no ongoing support obligation.

## Edition split

| Component | Public edition (view only) | Commercial edition |
|---|---|---|
| `classifier.py` (interface), `models.py`, `mock_classifier.py` | ✓ | ✓ |
| `prefilter.py` (local pre-filter) | ✓ | ✓ |
| `sieve.py` (gate with pre-filter and fail-secure handling) | ✓ | ✓ |
| `policy.py` (enforcement policy, reconfirmation, extra rules) | ✓ | ✓ |
| `demo/` with the replay recording of a live run | ✓ | ✓ |
| `docs/` (demo walkthrough, architecture, screenshots), README, this file | ✓ | ✓ |
| Tests for the parts above | ✓ | ✓ |
| The TypeSafe Jev adapter and its tuned question wording | — | ✓ |
| Adapter tests | — | ✓ |
| Evaluation tooling (blind-run, scoring and simulation scripts) | — | ✓ (as documentation of the method) |
| Blind payload sets and answer keys | — | — (internal) |
| Internal design and progress records | — | — (internal) |

The public edition runs on its own: the gate, the pre-filter, the policy and the replay demo need nothing from the commercial files. Live classification needs the commercial edition's adapter, so the public demo's live mode says so instead of running.

## The public edition: all rights reserved, view only

The public repository is published so people can see how SieveGate works. **It is not open source, and no open-source license applies to it.** All rights are reserved by the copyright holder.

- **You may** read the code and documentation, and run the included demo and tests on your own machine to evaluate SieveGate.
- **You may not** copy, modify, redistribute, sublicense or reuse any part of it, in whole or in part, in any other project or product, without written permission from the copyright holder.

The only other rights are the ones GitHub's Terms of Service give every user of a public repository (viewing it, and forking it within GitHub). These don't include any right to use, modify or distribute the code. For any other use, contact the copyright holder about a commercial license.

The commercial edition's source is private and is not covered by anything on this page.

## What a licensee receives

- The `sievegate` Python wheel. It is a plain wheel, not obfuscated.
- The documentation: README, architecture, demo walkthrough, and the evaluation method and results.
- A license certificate naming the licensed site.
- **Each buyer needs their own TypeSafe account and API key.** SieveGate calls TypeSafe's API with the buyer's key, and TypeSafe acts as the buyer's subprocessor for payloads the local pre-filter doesn't stop. The buyer should review TypeSafe's data-processing terms.

## Why there is no DRM

There is no license key, runtime license check, domain lock or code obfuscation. A runtime check would add support burden and new failure modes to a security component that has to fail closed and stay predictable. And mid-market buyers license software to stay compliant, not because they are forced to. The contract does the enforcing, not the code.

## Status

**Commercial terms are a draft and not offered for sale pending legal review.** The final contract wording is an open item.

Copyright © 2026 Ranjeet Reddy Manchana. All rights reserved.
