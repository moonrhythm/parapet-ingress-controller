# GeoIP test fixtures

Two tiny [IPLocate](https://github.com/iplocate/ip-address-databases)-shaped MMDBs
used by both implementations' GeoIP tests:

- `iplocate-country.mmdb` (**ip-to-country**) — Go `TestCountryIPLocateSchema`
  (`geoip/geoip_test.go`), Rust `geoip_decodes_iplocate_flat_schema` /
  `country_of_resolves_and_falls_back_to_xx` (`rust/controller/src/waf.rs`).
- `iplocate-asn.mmdb` (**ip-to-asn**) — Go `TestASNIPLocate`, Rust
  `asn_decodes_iplocate_flat_string` / `asn_of_resolves_and_zero_without_db`.

They exist to pin the **record schema**: IPLocate records are *flat* —
`country_code` / `asn` at the top level — unlike MaxMind GeoIP2, which nests
country under `country.iso_code`. The file format is a standard MMDB; only the
layout differs. A decoder that expects MaxMind's nested schema returns nothing
against the country DB, so these tests fail loudly if either implementation
regresses to it. The ip-to-asn `asn` is a *string* (e.g. `"15169"`) that the
resolver parses to an integer.

## Contents — `iplocate-country.mmdb`

| Network | `country_code` | continent | note |
|---|---|---|---|
| `8.8.8.0/24` | `US` | `NA` | |
| `1.1.1.0/24` | `AU` | `OC` | |
| `203.0.113.0/24` | `TH` | `AS` | TEST-NET-3 |
| `2001:db8::/32` | `DE` | `EU` | IPv6 documentation range |
| everything else (e.g. `192.0.2.0/24`, private ranges) | — | — | unmapped → no record |

Each record carries `continent_code`, `country_code`, and `country_name`,
mirroring IPLocate's real schema.

## Contents — `iplocate-asn.mmdb`

| Network | `asn` | org | note |
|---|---|---|---|
| `8.8.8.0/24` | `"15169"` | Google LLC | |
| `1.1.1.0/24` | `"13335"` | Cloudflare, Inc. | |
| `203.150.0.0/22` | `"4618"` | Internet Thailand | |
| `2001:db8::/32` | `"64500"` | Example Org | IPv6 + private-use ASN |
| everything else (e.g. `192.0.2.0/24`, private ranges) | — | — | unmapped → ASN 0 |

Each record carries `asn`, `name`, `org`, `domain`, and `country_code`,
mirroring IPLocate's real schema.

## Regenerating

The fixture is generated with [`mmdbwriter`](https://github.com/maxmind/mmdbwriter)
(kept out of the project modules — run it in a scratch dir):

```bash
mkdir /tmp/gengeoip && cd /tmp/gengeoip && go mod init gengeoip
go get github.com/maxmind/mmdbwriter@latest
# write main.go (see below), then:
go run . && cp iplocate-country.mmdb "$OLDPWD/conformance/geoip/"
```

```go
package main

import (
	"log"
	"net"
	"os"

	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
)

func main() {
	w, err := mmdbwriter.New(mmdbwriter.Options{
		DatabaseType:            "ip-to-country",
		Description:             map[string]string{"en": "parapet test ip-to-country (IPLocate flat schema)"},
		IPVersion:               6,
		RecordSize:              24,
		IncludeReservedNetworks: true,
	})
	if err != nil {
		log.Fatal(err)
	}
	insert := func(cidr, continent, cc, name string) {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			log.Fatal(err)
		}
		rec := mmdbtype.Map{
			"continent_code": mmdbtype.String(continent),
			"country_code":   mmdbtype.String(cc),
			"country_name":   mmdbtype.String(name),
		}
		if err := w.Insert(network, rec); err != nil {
			log.Fatal(err)
		}
	}
	insert("8.8.8.0/24", "NA", "US", "United States")
	insert("1.1.1.0/24", "OC", "AU", "Australia")
	insert("203.0.113.0/24", "AS", "TH", "Thailand")
	insert("2001:db8::/32", "EU", "DE", "Germany")

	f, err := os.Create("iplocate-country.mmdb")
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	if _, err := w.WriteTo(f); err != nil {
		log.Fatal(err)
	}
}
```

The ip-to-asn fixture is generated the same way, with `DatabaseType: "ip-to-asn"`
and flat string records (note `asn` is a `mmdbtype.String`):

```go
	insert := func(cidr, asn, name, org, domain, cc string) {
		_, network, _ := net.ParseCIDR(cidr)
		rec := mmdbtype.Map{
			"asn":          mmdbtype.String(asn),
			"name":         mmdbtype.String(name),
			"org":          mmdbtype.String(org),
			"domain":       mmdbtype.String(domain),
			"country_code": mmdbtype.String(cc),
		}
		_ = w.Insert(network, rec)
	}
	insert("8.8.8.0/24", "15169", "GOOGLE", "Google LLC", "google.com", "US")
	insert("1.1.1.0/24", "13335", "CLOUDFLARENET", "Cloudflare, Inc.", "cloudflare.com", "US")
	insert("203.150.0.0/22", "4618", "INET-TH-AS", "Internet Thailand Company Ltd.", "inet.co.th", "TH")
	insert("2001:db8::/32", "64500", "TEST-AS", "Example Org", "example.com", "DE")
	// -> iplocate-asn.mmdb
```

This is synthetic test data, not a redistribution of IPLocate's database.
