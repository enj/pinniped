package controllermanager

import (
	"net/url"
	"testing"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	restclient "k8s.io/client-go/rest"

	"go.pinniped.dev/test/library"
)

func Test_setClientContentConfig(t *testing.T) {
	rc, _ := restclient.NewRESTClient(
		&url.URL{},
		"",
		restclient.ClientContentConfig{AcceptContentTypes: "LOL"},
		nil,
		nil,
	)
	setClientContentConfig(rc, func(config *restclient.ClientContentConfig) {
		config.AcceptContentTypes = "NOTlzzz"
		config.Negotiator = runtime.NewClientNegotiator(nil, schema.GroupVersion{})
	})
	t.Error(library.Sdump(rc))
}
