package kubeclient

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"mime"
	"net/http"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apiserver/pkg/server"
	restclient "k8s.io/client-go/rest"
)

func configWithWrapper(config *restclient.Config, codecs serializer.CodecFactory, ref metav1.OwnerReference) *restclient.Config {
	negotiatedSerializer := codecs.WithoutConversion()
	resolver := server.NewRequestInfoResolver(server.NewConfig(codecs))

	f := func(rt http.RoundTripper) http.RoundTripper {
		return roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			// ignore everything that is not a create or has an unreadable body
			if req.Method != http.MethodPost || req.GetBody == nil {
				return rt.RoundTrip(req)
			}

			body, err := req.GetBody()
			if err != nil {
				return nil, fmt.Errorf("get body failed: %w", err)
			}
			defer body.Close()
			data, err := ioutil.ReadAll(body)
			if err != nil {
				return nil, fmt.Errorf("read body failed: %w", err)
			}

			requestInfo, e8 := resolver.NewRequestInfo(req)

			gv := schema.GroupVersion{Group: requestInfo.APIGroup, Version: requestInfo.APIVersion}
			negotiator := runtime.NewClientNegotiator(negotiatedSerializer, gv)

			contentType := req.Header.Get("Content-Type")
			mediaType, params, e1 := mime.ParseMediaType(contentType)

			decoder, e2 := negotiator.Decoder(mediaType, params)
			obj, _, e3 := decoder.Decode(data, nil, nil)

			if !needsOwnerRef(obj) {
				return rt.RoundTrip(req)
			}

			_ = req.Body.Close()

			setOwnerRef(obj, ref)

			encoder, e6 := negotiator.Encoder(mediaType, params)

			newData, e7 := runtime.Encode(encoder, obj)

			// TODO log newData at high loglevel

			newReqForBody, e4 := http.NewRequestWithContext(req.Context(), req.Method, req.URL.String(), bytes.NewReader(newData))

			// we want to preserve all the headers and such
			newReq := req.Clone(req.Context())
			newReq.Body = newReqForBody.Body
			newReq.GetBody = newReqForBody.GetBody

			return rt.RoundTrip(newReq)
		})
	}

	cc := restclient.CopyConfig(config)
	cc.Wrap(f)
	return cc
}

type roundTripperFunc func(req *http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
