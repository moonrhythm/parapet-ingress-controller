// Package wafrule parses the YAML rule documents carried in WAF ConfigMaps
// (the global ruleset and per-zone rulesets) into parapet waf.Rule values.
//
// It is deliberately a thin DTO layer: it converts YAML to []waf.Rule and maps
// the `action` string onto waf.Action, then hands off to waf.WAF.SetRules,
// which is the single source of truth for the heavier validation (empty ID,
// duplicate ID, empty/non-bool/uncompilable expression) and for the
// all-or-nothing compile.
package wafrule

import (
	"errors"
	"fmt"
	"strings"

	"github.com/moonrhythm/parapet/pkg/waf"
	"gopkg.in/yaml.v3"
)

// Document is the YAML shape of a WAF ConfigMap data value.
type Document struct {
	Rules []Rule `yaml:"rules"`
}

// Rule mirrors waf.Rule with YAML tags. Action is a string here ("log",
// "allow", "block") and converted to waf.Action by Parse.
type Rule struct {
	ID          string `yaml:"id"`
	Description string `yaml:"description"`
	Expression  string `yaml:"expression"`
	Action      string `yaml:"action"`
	Status      int    `yaml:"status"`
	Message     string `yaml:"message"`
	Priority    int    `yaml:"priority"`
}

// ParseAction maps an action string onto waf.Action. An empty action defaults
// to ActionLog (a safe shadow rule that never blocks), matching waf.Action's
// zero value.
func ParseAction(s string) (waf.Action, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "log":
		return waf.ActionLog, nil
	case "allow":
		return waf.ActionAllow, nil
	case "block":
		return waf.ActionBlock, nil
	default:
		return 0, fmt.Errorf("unknown action %q (want log|allow|block)", s)
	}
}

// Parse parses one or more YAML rule documents (each ConfigMap data value is one
// document) and returns the concatenated []waf.Rule. A YAML or action error in
// any document is collected and returned joined; the caller (SetRules) rejects
// the whole batch on any error, so a bad document never partially applies.
func Parse(docs ...string) ([]waf.Rule, error) {
	var out []waf.Rule
	var errs []error
	for _, doc := range docs {
		if strings.TrimSpace(doc) == "" {
			continue
		}
		var d Document
		if err := yaml.Unmarshal([]byte(doc), &d); err != nil {
			errs = append(errs, fmt.Errorf("waf: parse document: %w", err))
			continue
		}
		for i, r := range d.Rules {
			action, err := ParseAction(r.Action)
			if err != nil {
				errs = append(errs, fmt.Errorf("waf: rule[%d] %q: %w", i, r.ID, err))
				continue
			}
			out = append(out, waf.Rule{
				ID:          r.ID,
				Description: r.Description,
				Expression:  r.Expression,
				Action:      action,
				Status:      r.Status,
				Message:     r.Message,
				Priority:    r.Priority,
			})
		}
	}
	return out, errors.Join(errs...)
}
