package plugin

import (
	"net/http"

	"github.com/moonrhythm/parapet"
	"k8s.io/api/extensions/v1beta1"
)

// Plugin injects middleware or mutate router while reading ingress object
type Plugin func(ctx Context)

// Context holds plugin's relate data
type Context struct {
	*parapet.Middlewares
	Mux     *http.ServeMux
	Ingress *v1beta1.Ingress
}
