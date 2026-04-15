# Dataset Documentation

## Overview

This document describes the forensic datasets used for testing and demonstrating the IABF Agent.

## Acquired Datasets

### Dataset: NIST CFReDS — Hacking Case ("Greg Schardt / Mr. Evil")

| Field | Value |
|-------|-------|
| **Source** | https://cfreds-archive.nist.gov/Hacking_Case.html |
| **Type** | Disk image (fixed disk, 4.5 GiB raw) |
| **Format** | EnCase 4 (E01 + E02 segments) |
| **Files** | `datasets/hacking_case/4Dell_Latitude_CPi.E01` (671,094,597 B), `.E02` (419,384,951 B) |
| **SHA256 (.E01)** | `96bebe80f00541bf28fbc2ef0b02b580082ee6ad58837e991852ae66f077ec31` |
| **SHA256 (.E02)** | `46bd09821dbb64675e5877d0ad7ec544a571fad5a3fd7fc3f0c3a16278887db5` |
| **MD5 (acquired, embedded in E01)** | `aee4fcd9301c03b3b054623ca261959a` ✅ matches ground truth |
| **Acquired by** | Shane Robinson, EnCase 4.19a, 2004-09-22 |
| **Scenario** | Dell CPi notebook (SN VLQLW) abandoned with wireless card + homemade antenna, suspected wardriving by Greg Schardt aka "Mr. Evil" |
| **Ground truth** | `reports/ground_truth/hacking_case.json` (31 questions) |

Verification command used:
```
ewfinfo 4Dell_Latitude_CPi.E01   # confirms embedded MD5
ewfverify 4Dell_Latitude_CPi.E01 # re-hashes raw stream
```

---

## Dataset Template

For each dataset used, document the following:

### Dataset: [Name]

| Field | Value |
|-------|-------|
| **Source** | Where the dataset came from (e.g., NIST CFReDS, created for testing) |
| **Type** | Disk image / Memory capture / Network capture / Log files |
| **Format** | E01 / raw / dd / pcap / evtx / etc. |
| **Size** | File size |
| **Hash (SHA256)** | Integrity verification hash |
| **Contents** | What the dataset contains |
| **Known Findings** | Ground truth — what should be found |
| **Agent Findings** | What the IABF agent actually found |
| **Accuracy** | Comparison of expected vs actual findings |

## Recommended Test Datasets

### Public Forensic Image Sources

1. **NIST CFReDS** — Computer Forensic Reference Data Sets
   - Validated datasets with known ground truth
   - Ideal for accuracy benchmarking

2. **Digital Corpora** — digitalcorpora.org
   - Various disk images, network captures
   - Well-documented scenarios

3. **SANS Holiday Hack / CTF Images**
   - Realistic incident scenarios
   - Multiple evidence types

4. **Volatility Foundation Sample Images**
   - Memory dumps with known malware
   - Good for memory analysis testing

## Evidence Integrity

All evidence files must be:
- Hashed (SHA256) before and after analysis
- Mounted read-only when accessed by the agent
- Never modified by any tool execution (enforced by guardrails)

## Findings Documentation Format

For each investigation run, document:

```
Investigation ID: [session_id]
Dataset: [name]
Date: [timestamp]

Expected Findings (Ground Truth):
1. [finding]
2. [finding]

Agent Findings:
1. [finding] — CONFIRMED / MISSED
2. [finding] — CONFIRMED / MISSED
3. [unexpected finding] — FALSE POSITIVE / TRUE POSITIVE

Accuracy Metrics:
- True Positives: X
- False Positives: X
- False Negatives (Missed): X
- Precision: X%
- Recall: X%
```
