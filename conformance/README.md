# Conformance fixtures

Implementation-neutral test cases that pin the [behavior contract](../SPEC.md):
a behavior is specified once here, and the test suite asserts it. The fixtures
predate the removal of the Rust port (they originally kept two co-maintained
controllers in lock-step); they remain **normative** — they define the
supported surface, not just whatever the code happens to do today.

## Status

Seeded, growing. Today the Go test suite keeps its own assertions; these
fixtures are the **canonical specification** they track, and the long-term goal
is for the test suite to load directly from this directory so a contract
change can't land in code without the fixture being updated to match.

| Fixture | Specifies | Asserted in |
|---|---|---|
| [`waf-cel-corpus.md`](waf-cel-corpus.md) | CEL rule strings evaluate per the pinned semantics | `wafrule/*_test.go` + parapet `pkg/waf` tests |
| _(routing, annotations — to add)_ | PathType registration, annotation→behavior | `controller_test.go`, `plugin/*_test.go` |

## Why the CEL corpus matters most

WAF rules are operator-authored CEL strings that live in tenant ConfigMaps, not
in this repo — they can't be recompiled or audited when the engine changes. The
corpus pins the rule-authoring surface (custom functions, the `request` map,
normalization) so an upgrade of cel-go / `parapet/pkg/waf` can't silently
change what a rule matches. A divergence here means a rule that used to block
silently passes (or vice-versa) — the corpus is the regression guard against
exactly that.
