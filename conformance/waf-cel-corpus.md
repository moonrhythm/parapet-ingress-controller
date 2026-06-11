# WAF CEL corpus

Canonical CEL rule strings whose results are **pinned**: they must keep
evaluating exactly as specified here under the controller's engine (cel-go, via
`parapet/pkg/waf`), including across cel-go / `parapet/pkg/waf` upgrades.
Each case is a rule `expression`, the request fields it reads, and whether it
should **block** (expression → `true`) with `action: block`.

Request fields are the `request.*` map from [SPEC.md](../SPEC.md) / [WAF.md](../WAF.md).
`headers`/`args`/`cookies` keys are lowercased; `query` is the **raw** query
string (not decoded); `args` are decoded first-values.

## Request variables

| # | expression | request | blocks? |
|---|---|---|---|
| 1 | `request.method == "DELETE"` | method=DELETE | yes |
| 2 | `request.headers["x-bad"] == "1"` | header `X-Bad: 1` | yes |
| 3 | `request.user_agent.contains("sqlmap")` | UA `sqlmap/1.0` | yes |
| 4 | `request.args["id"] == "../../etc/passwd"` | `?id=../../etc/passwd` | yes |
| 5 | `request.cookies["session"] == "stolen"` | cookie `session=stolen` | yes |
| 6 | `request.path.startsWith("/admin")` | path `/admin/users` | yes |
| 7 | `request.path.startsWith("/admin")` | path `/public` | no |

## Custom functions

| # | expression | request | blocks? |
|---|---|---|---|
| 8 | `ipInCidr(request.remote_ip, "10.0.0.0/8")` | remote_ip `10.5.6.7` | yes |
| 9 | `ipInCidr(request.remote_ip, "10.0.0.0/8")` | remote_ip `8.8.8.8` | no |
| 10 | `regexMatch(lower(urlDecode(request.query)), "(union\\s+select\|or\\s+1=1)")` | `?q=1+UNION+SELECT+pass` | yes |
| 11 | `containsAny(lower(request.user_agent), ["sqlmap","nikto","acunetix"])` | UA `Mozilla/5.0 NIKTO scanner` | yes |
| 12 | `hasPrefixAny(request.path, ["/admin","/internal","/.git"])` | path `/.git/config` | yes |
| 13 | `urlDecode(request.query).contains("../")` | `?file=%2E%2E%2Fetc%2Fpasswd` | yes |
| 14 | `upper(request.method) == "GET"` | method `get` | yes |

## GeoIP (`request.country`)

`request.country` is the GeoIP country (ISO 3166-1 alpha-2). It is **always
present** — `""` (GeoIP off), `"XX"` (DB loaded, IP unresolved), or a code — so a
rule referencing it never errors on a missing key.

| # | expression | request.country | blocks? |
|---|---|---|---|
| 15 | `request.country == "CN"` | `CN` | yes |
| 16 | `request.country == "CN"` | `TH` | no |
| 17 | `containsAny(request.country, ["CN", "RU", "KP"])` | `RU` | yes |
| 18 | `request.country != "TH"` (allow-list) | `XX` (unknown) | yes |
| 19 | `request.country != "TH"` (allow-list) | `TH` | no |

## GeoIP (`request.asn`)

`request.asn` is the GeoIP autonomous system number (an integer). It is **always
present** — `0` when ASN lookup is off or the IP can't be placed (RFC 7607
reserved), otherwise the AS number — so a rule referencing it never errors on a
missing key.

| # | expression | request.asn | blocks? |
|---|---|---|---|
| 20 | `request.asn == 13335` | `13335` | yes |
| 21 | `request.asn == 13335` | `15169` | no |
| 22 | `request.asn == 0` (unknown) | `0` | yes |
| 23 | `request.asn != 4808` (allow-list) | `0` (unknown) | yes |
| 24 | `request.asn != 4808` (allow-list) | `4808` | no |

## Pinned semantics

- **Actions**: `block` terminates (status/message); `allow` short-circuits *this
  ruleset only* and proceeds; `log` records and continues. Rules run ascending by
  `priority` (stable on ties).
- **`urlDecode`** = Go `url.QueryUnescape`: `+`→space, `%XX`→byte, malformed `%`→`""`.
- **Bad input is fail-open by default**: a rule that errors at evaluation
  (uncompilable-at-runtime regex, missing map key, non-bool result) is logged and
  skipped unless `WAF_FAIL_MODE=closed`.
- **Empty ruleset / no match** → request proceeds.
