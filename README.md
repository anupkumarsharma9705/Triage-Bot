# Reachability-Aware Vulnerability Triage Bot

A Spring Boot service that ingests SCA (dependency vulnerability) scan results,
checks whether each vulnerable class is actually **reachable** in the target
codebase, scores findings by real risk instead of raw CVSS, and posts a
ranked report as a GitHub PR comment via CI.

**Problem it addresses:** SCA scanners flag every CVE in your dependency tree
by CVSS score alone, regardless of whether your code ever uses the vulnerable
class. This creates alert fatigue — teams end up triaging dozens of findings
manually to find the handful that matter. This tool adds a reachability
filter as a first-pass signal.

## Limitations

- **Import-level, not method-call-level.** Checks whether a vulnerable
  package is imported and referenced textually — does not trace whether the
  specific vulnerable *method* is invoked, and does not build a call graph.
- **No reflection or dependency-injection awareness.** Classes instantiated
  via reflection or resolved dynamically by a DI container won't be detected
  even if genuinely reachable.
- **Single-module Maven projects only.** Not tested against multi-module repos.
- **No runtime/dynamic tracing.** Purely static, source-level analysis.
- **Scoring formula is a simple multiplier** (`cvss × reachMult × exposureMult`),
  not calibrated against real incident data.
- **Ingest format is simplified**, not raw OWASP Dependency-Check JSON — a
  mapping step would be needed to consume real DC scanner output directly.

A production tool (e.g. Endor Labs, Semgrep Reachability) addresses these
gaps with bytecode analysis and runtime instrumentation.

## Architecture

Dependency-check JSON
↓
/api/ingest endpoint (parses report, saves findings)
↓
Reachability analyzer (checks imports via JavaParser)
↓
H2 database (findings marked reachable / not)
↓
/api/report (ranked by risk score)
↓
GitHub Actions (posts ranked table as PR comment)


## Tech Stack

Java 21, Spring Boot 3.x, Spring Data JPA, H2, JavaParser, GitHub Actions.

## How to Run

```bash
mvn clean package -DskipTests
java -jar target/triage-bot-0.1.0.jar
```

Ingest a report against a target codebase:

```bash
curl -X POST "http://localhost:8080/api/ingest?sourceRoot=<path-to-java-source>" \
  -H "Content-Type: application/json" \
  --data @sample-report.json
```

Get the ranked report:

```bash
curl http://localhost:8080/api/report
```

## Sample Output

Tested against a real Spring Boot project (external repo, not authored by
this project) with 3 sample CVEs:

| CVE | Dependency | Reachable | Manually verified |
|---|---|---|---|
| CVE-TEST-REAL | jjwt | true | Confirmed: `io.jsonwebtoken.Jwts` genuinely imported in target's JWT filter |
| CVE-2022-5678 | commons-text-1.9.jar | false | Confirmed: no import found anywhere in target source |
| CVE-2021-9999 | log4j-core-2.14.1.jar | false | Confirmed: no import found anywhere in target source |

3 of 3 tool verdicts matched manual source inspection. Small sample size —
not a large-scale validation.

## CI Integration

See `.github/workflows/security-gate.yml` — runs on every pull request,
builds and starts the service, ingests `sample-report.json` against the
checked-out source, and posts the ranked findings as a PR comment.

## How to Extend

- Method-level reachability via call-graph traversal (deeper JavaParser usage
  or Soot bytecode analysis)
- Real OWASP Dependency-Check JSON parsing (mapping layer)
- Multi-module Maven support
- Scoring formula calibration against real incident/exploit data