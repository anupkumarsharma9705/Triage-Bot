# Reachability-Aware Vulnerability Triage Bot

A Spring Boot service that ingests SCA (dependency vulnerability) scan
results, checks whether each vulnerable class is actually **reachable**
in a target codebase, and (eventually) produces a risk-ranked report.

**Status: in progress.** See Build Log at the bottom for what's done vs. not.

---

## Problem statement

SCA scanners (e.g. OWASP Dependency-Check) report every known CVE in your
dependency tree, regardless of whether your code actually uses the
vulnerable class. This causes alert fatigue — teams triage dozens of
findings that pose no real risk because the vulnerable code path is
never executed. This tool adds a reachability signal on top of raw
CVSS scores to help prioritize what's actually worth fixing first.

---

## Architecture

```
Dependency-Check JSON
        │
        ▼
POST /api/ingest (sourceRoot, report)
        │
        ├─► ReachabilityAnalyzer (JavaParser)
        │     scans sourceRoot's .java files for
        │     import-level references to each
        │     vulnerable class
        │
        └─► Finding entity (persisted via JPA/H2)
                cveId, dependencyName, vulnerableClass,
                cvssScore, reachable, riskScore, scannedAt
```

Planned (not yet built): `RiskScoringService`, `/api/report`,
GitHub Actions integration, PR comment posting.

---

## What "reachable" means here (read this before trusting the output)

Reachability in this tool is **import-level only**:

> Does any `.java` file in the scanned source tree import the vulnerable
> package, or textually reference the vulnerable class's simple name in
> a method call?

This is **not** call-graph analysis. It does not confirm the specific
vulnerable *method* is actually invoked, does not trace execution paths,
and does not understand reflection or dependency injection. A class
that's imported but never actually used in a risky way will still be
flagged reachable (false positive risk). A class instantiated only via
reflection or DI without a direct import may be missed (false negative
risk).

Full limitations list is at the bottom, and will be expanded after
manual validation (planned for the "Honesty Fixes" pass).

---

## Tech stack

| Purpose | Tool |
|---|---|
| Backend | Spring Boot 3.3.4 (Web, JPA) |
| Reachability parsing | JavaParser (`javaparser-core`) |
| Persistence | H2 (in-memory, dev) |
| JSON | Jackson (bundled with Spring Web) |

---

## How to run it

Requires Java 21 and Maven.

```bash
mvn spring-boot:run
```

Ingest a sample report:

```powershell
Invoke-RestMethod -Uri "http://localhost:8080/api/ingest?sourceRoot=C:\path\to\source" `
  -Method Post -ContentType "application/json" -InFile "sample-report.json"
```

```bash
curl.exe -X POST "http://localhost:8080/api/ingest?sourceRoot=/path/to/source" \
  -H "Content-Type: application/json" --data "@sample-report.json"
```

`sourceRoot` must point at a real directory of `.java` files — the code
being checked for reachability, not this project itself (though pointing
it at this project's own `src` works fine as a test).

Inspect persisted data via H2 console: `http://localhost:8080/h2-console`
JDBC URL: `jdbc:h2:mem:triagebot`, user `sa`, blank password.

---

## Known limitations (updated as found)

- Reachability is import-level, not method-call-level.
- No support for reflection-based instantiation or DI resolving classes
  dynamically.
- No call-graph traversal — a file that imports a package but never
  calls the vulnerable method is still flagged reachable.
- Single-directory scans only — not tested against multi-module Maven
  projects.
- No runtime/dynamic tracing — purely static, source-level analysis.
- `DependencyCheckReport` is a simplified flat JSON shape, not the real
  nested OWASP Dependency-Check schema — real DC output needs a mapping
  step before it can be ingested as-is.
- Risk scoring formula (once built) will be a simple multiplier, not
  calibrated against real incident data.

---

## Build Log

**Day 1 AM** — Spring Boot skeleton, `Finding` entity, H2 config,
`FindingRepository`, `/api/ingest` parsing a flattened sample JSON and
persisting `Finding` rows.

**Day 1 PM** — `ReachabilityAnalyzer` (JavaParser, import-level scan)
wired into `/api/ingest` via a new `sourceRoot` request parameter. Each
`Finding` gets `reachable` set before saving. Fails safe: if analysis
throws, `reachable` defaults to `true` (avoids silently hiding a
possible risk).

**Day 2 AM** — *not yet done.* Planned: `RiskScoringService`,
`/api/report`.

**Day 2 PM** — *not yet done.* Planned: GitHub Actions workflow, PR
comment posting.

**Day 3** — *not yet done.* Planned: manual validation of 10-15
findings against real source, precise naming pass, expanded limitations
section, final polish.
