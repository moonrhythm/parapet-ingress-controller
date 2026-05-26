# Conformance fixtures

Language-neutral test cases that **both** implementations are expected to
satisfy identically. This is the mechanism that keeps two co-maintained
controllers honest about the shared [behavior contract](../SPEC.md): a behavior
is specified once here, and each implementation's test suite asserts it.

## Status

Seeded, growing. Today each implementation keeps its own assertions; these
fixtures are the **canonical specification** they track, and the long-term goal
is for both test suites to load directly from this directory so a contract
change can't land in one implementation without the other.

| Fixture | Specifies | Go asserts in | Rust asserts in |
|---|---|---|---|
| [`waf-cel-corpus.md`](waf-cel-corpus.md) | CEL rule strings evaluate identically (cel-go ↔ cel-rust) | `go/wafrule/*_test.go` + parapet `pkg/waf` tests | `rust/controller/src/waf.rs` (`corpus_*` tests) |
| _(routing, annotations — to add)_ | PathType registration, annotation→behavior | `go/controller_test.go`, `go/plugin/*_test.go` | `rust/controller/src/{router,config,proxy}.rs` |

## Why a shared CEL corpus matters most

The WAF lets operators author the *same* CEL rule string and run it under either
controller. cel-go and cel-rust are different engines, so the corpus pins the
cases where they must agree (custom functions, the `request` map, normalization).
A divergence here means a rule that blocks under Go silently passes under Rust
(or vice-versa) — the corpus is the regression guard against exactly that.
