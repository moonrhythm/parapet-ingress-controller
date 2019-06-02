package main

import (
	"encoding/base64"
	"strings"

	"github.com/acoshift/configfile"
)

type _config struct {
	*configfile.Reader
}

var config = _config{configfile.NewEnvReader()}

func (c _config) Strings(name string) []string {
	s := c.String(name)
	return strings.Split(s, ",")
}

func (c _config) Base64(name string) []byte {
	s := c.String(name)
	if s == "" {
		return nil
	}
	b, _ := base64.StdEncoding.DecodeString(s)
	return b
}
