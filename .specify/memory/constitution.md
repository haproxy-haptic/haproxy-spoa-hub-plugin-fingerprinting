<!--
Sync Impact Report
===================
Version change: 0.0.0 → 1.0.0 (initial ratification)
Added principles:
  - I. Code Quality
  - II. Testing Standards
  - III. User Experience Consistency
  - IV. Performance Requirements
Added sections:
  - Development Standards
  - Quality Gates
  - Governance
Removed sections: none
Templates requiring updates:
  - .specify/templates/plan-template.md ✅ no updates needed (Constitution Check section is generic)
  - .specify/templates/spec-template.md ✅ no updates needed (success criteria align with performance principle)
  - .specify/templates/tasks-template.md ✅ no updates needed (phase structure supports test-first and polish phases)
Follow-up TODOs: none
-->

# HAProxy SPOA Hub Plugin Fingerprinting Constitution

## Core Principles

### I. Code Quality

All code MUST be clear, maintainable, and minimal. Specifically:

- Functions and modules MUST have a single, well-defined responsibility.
- Public APIs MUST be documented with purpose, parameters, and return values.
- Dead code, unused imports, and unreachable branches MUST be removed before merge.
- Code duplication MUST be extracted into shared functions when the same logic
  appears in more than two locations.
- Naming MUST accurately reflect purpose — misleading names MUST be corrected
  immediately upon discovery.
- External inputs (SPOA messages, configuration values, network data) MUST be
  validated at system boundaries. Internal function calls between trusted
  modules SHOULD NOT add redundant validation.

### II. Testing Standards (NON-NEGOTIABLE)

Test-Driven Development is mandatory for all bug fixes and new features:

- **Bug fixes**: A failing test MUST reproduce the bug before any fix is
  implemented. The fix MUST make that test pass.
- **New features**: Tests MUST be written first when feasible. The Red-Green-Refactor
  cycle MUST be followed.
- **Test independence**: Each test MUST be independently runnable and MUST NOT
  depend on execution order or shared mutable state.
- **Integration tests**: MUST use real dependencies (real HAProxy instances,
  real SPOA connections) where practical. Mocks are permitted only for
  external services outside the project's control.
- **Coverage expectation**: All public API surfaces and protocol handling paths
  MUST have corresponding tests. Edge cases (malformed fingerprints, connection
  drops, oversized payloads) MUST be covered.

### III. User Experience Consistency

The plugin MUST behave predictably and transparently for HAProxy operators:

- Configuration syntax MUST follow HAProxy conventions. Operators familiar with
  HAProxy SPOA configuration MUST NOT need to learn novel patterns.
- Error messages MUST be actionable: they MUST state what went wrong, which
  input caused it, and what the operator can do to fix it.
- Logging MUST use structured formats and severity levels consistently.
  DEBUG for internal state, INFO for operational events, WARN for recoverable
  issues, ERROR for failures requiring operator attention.
- Behavioral changes between versions MUST be documented in a changelog.
  Breaking changes MUST follow semantic versioning rules and MUST be announced
  with at least one minor release of deprecation notice where feasible.

### IV. Performance Requirements

As a data-path plugin in HAProxy's request processing pipeline, performance
is a first-class concern:

- Fingerprint computation MUST NOT add more than 1ms of latency per request
  at the 99th percentile under normal operating conditions.
- Memory allocation per request MUST be bounded and predictable. The plugin
  MUST NOT accumulate unbounded state across requests.
- The plugin MUST handle connection drops and malformed SPOA frames gracefully
  without leaking resources (file descriptors, memory, goroutines/threads).
- Performance-critical paths MUST have benchmarks. Regressions exceeding 10%
  on existing benchmarks MUST be justified and documented before merge.

## Development Standards

- All changes MUST pass linting, formatting, and the full test suite before
  merge.
- Commit messages MUST be descriptive and follow conventional commits format.
- Dependencies MUST be pinned to specific versions. Dependency updates MUST
  be isolated in dedicated commits to simplify bisection.
- Security-sensitive code (cryptographic operations, input parsing, network
  handling) MUST receive explicit review attention.

## Quality Gates

Every pull request MUST satisfy the following before merge:

1. All existing tests pass.
2. New code includes tests per Principle II.
3. No linter warnings introduced.
4. Performance benchmarks show no unexplained regression per Principle IV.
5. Documentation updated if user-facing behavior changed per Principle III.
6. Constitution compliance verified — deviations MUST be justified in the PR
   description with rationale.

## Governance

This constitution is the authoritative source for development standards in
this project. In case of conflict between this document and other guidance,
this constitution takes precedence.

- **Amendments**: Any change to this constitution MUST be proposed as a pull
  request, reviewed, and approved before merge. The amendment MUST include
  an updated version number and date.
- **Versioning**: The constitution follows semantic versioning. MAJOR for
  principle removals or incompatible redefinitions, MINOR for new principles
  or material expansions, PATCH for clarifications and wording fixes.
- **Compliance**: All pull requests and code reviews MUST verify compliance
  with these principles. Non-compliance MUST be flagged and resolved before
  merge.

**Version**: 1.0.0 | **Ratified**: 2026-04-06 | **Last Amended**: 2026-04-06
