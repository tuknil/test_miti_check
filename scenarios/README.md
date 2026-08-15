# Sample run scenarios

Four ready-to-run request payloads, one per confusion-matrix quadrant. Open a
file, copy its contents, paste into the **Request payload (JSON)** box on the
landing page, and click **Submit run**. Each is a complete, valid
`SubmitMitigationCheckRequest@1` body.

All four use the same substrate — the real `ghcr.io/christophetd/log4shell-vulnerable-app`
container (CVE-2021-44228 / Log4Shell). What varies is the candidate **WAF rule**
and the **test request**.

| File | Quadrant | Rule | Request | Result |
|---|---|---|---|---|
| [`01-true-positive.json`](01-true-positive.json) | **TP** — attack correctly blocked | strict JNDI rule (`1005440`) | `${jndi:ldap://…}` attack | `blocked`, **match ✓** |
| [`02-true-negative.json`](02-true-negative.json) | **TN** — benign correctly allowed | strict JNDI rule (`1005440`) | normal request (`X-Api-Version: 2.11.0`) | `not-blocked`, **match ✓** |
| [`03-false-positive.json`](03-false-positive.json) | **FP** — benign wrongly blocked | over-broad rule (`1005450`, matches any `jndi`) | benign page `/articles/mitigating-jndi-injection-in-java` | `blocked`, **match ✗** |
| [`04-false-negative.json`](04-false-negative.json) | **FN** — attack slips through | naive rule (`1005460`, literal `${jndi:` only) | obfuscated `${${lower:j}${lower:n}…}` bypass | `not-blocked`, **match ✗** |

## How to read the outcome

- **`terminal_state`** is what actually happened to the request: `blocked` (WAF
  denied it) or `not-blocked` (it reached the live app).
- **`match`** is whether that equals `expected.blocked`. `true` = the WAF behaved
  correctly (TP, TN); `false` = the WAF was wrong (FP, FN).

So the two failure quadrants are exactly the runs where `match` is `false`:

- **False positive** — legitimate traffic denied. Here an over-broad rule blocks a
  documentation page just because the path contains the string `jndi`.
- **False negative** — a real attack not denied. Here a naive rule that only looks
  for the literal `${jndi:` misses the well-known `${lower:}` obfuscation, and the
  exploit request reaches the vulnerable app.

## Run from the CLI instead

```bash
curl -s -X POST localhost:8137/v1/mitigation-check-runs \
  -H 'Content-Type: application/json' \
  --data-binary @scenarios/03-false-positive.json | python3 -m json.tool
```
