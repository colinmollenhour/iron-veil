# IronVeil v0.1.1 Release Notes

Release date: February 25, 2026

## Summary

v0.1.1 is a quality and reliability release focused on rule-management correctness, PostgreSQL runtime behavior, frontend/API hardening, and documentation accuracy.

This release includes two important behavior fixes:
- Masking rule writes are now idempotent and deduplicated by target (`table` + `column`).
- PostgreSQL runtime masking now supports table-scoped rules by resolving table OIDs at session bootstrap.

## Highlights

### 1. Rule Management Correctness

- `POST /rules` now performs upsert semantics for existing targets instead of creating duplicates.
- `POST /rules/import` deduplicates existing and imported duplicates.
- Target uniqueness is normalized case-insensitively by `(table, column)`.
- Added regression tests for upsert and import dedup behavior.

Impact:
- Prevents duplicate rules from accumulating.
- Ensures repeated apply/import operations are safe and predictable.

### 2. PostgreSQL Table-Scoped Runtime Matching

- Added PostgreSQL table OID bootstrap mapping at session startup.
- Runtime masking now applies table-scoped rules when OID resolution succeeds.
- Safe fallback remains in place: global column rules apply when OID resolution is unavailable.
- Added dedicated tests for both resolved and unresolved paths.

Impact:
- Brings PostgreSQL runtime behavior in line with user expectations for table-scoped rules.

### 3. Frontend API Robustness

- Hardened frontend API error handling across dashboard pages.
- Added stricter settings response validation and safer config reads.
- Scan page now correctly reflects persisted applied rules after refresh by hydrating from backend rules.
- Added regression coverage for scan page persisted apply-state.

Impact:
- Better user feedback and fewer silent failures.
- UI state now matches backend persisted state.

### 4. Scan and Health API Improvements

- Added scan credential validation and documented scan error codes.
- Exposed richer health runtime metadata in settings and docs.

Impact:
- Clearer operational diagnostics and more actionable scan failures.

## Additional Changes Included Since v0.1.0

- Refactored web API client and scan input handling.
- Added settings UI for API auth overrides.
- Strengthened integration endpoint assertions.
- Ignored `.next` artifacts in Jest discovery.
- Improved hash masking strategy semantics.
- Updated roadmap and architecture/documentation alignment.

## Testing and Verification

Validated in this release cycle:
- Rust: `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo test`
- Web: `npm run lint`, `npm test -- --runInBand`, `npm run build`
- Live backend verification against Dockerized services:
  - rules upsert/dedup behavior via API
  - PostgreSQL table-scoped runtime masking behavior via proxy + `/logs`

## Upgrade Notes

- No breaking API contract changes for existing endpoints.
- If you rely on duplicate rule entries, behavior is now normalized and deduplicated by target.
- PostgreSQL deployments using table-scoped rules should validate expected masking outcomes in staging before production rollout.

## Commits Included (v0.1.0..v0.1.1)

- `f94df0e` Add strategic backlog to roadmap
- `7d8c0e6` Persist scan applied-state from backend rules
- `2b89336` Enable PostgreSQL table-scoped runtime matching
- `e70111b` Prevent duplicate masking rules with upsert semantics
- `87c2ddc` Harden frontend API error handling across pages
- `e716d22` Harden settings API response validation
- `61b5381` Expose health runtime metadata in settings and docs
- `d2ecfd8` Validate scan credentials and document scan error codes
- `12ecf7d` Remove stale hard-coded test counts from README
- `6dca330` Strengthen integration endpoint assertions
- `6e471db` Add settings UI for API auth overrides
- `e739edc` Ignore .next artifacts in Jest discovery
- `43aad5e` Refactor web API client and configurable scan inputs
- `a900fe8` Harden API error semantics and hash masking strategy
- `b160680` Harden PostgreSQL table-scoped rule matching
- `25e0908` Make metrics initialization idempotent
- `4f1bbe8` Fix API scan flow quality issues and align docs
- `dee3078` chore: remove unused favicon.ico file
- `de11ec2` Add settings API wiring and Jest tests
- `134b44b` fix(roadmap): update Prometheus metrics section and audit summary

