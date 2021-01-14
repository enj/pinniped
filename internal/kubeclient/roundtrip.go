// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package kubeclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"mime"
	"net/http"
	"net/url"
	"path"
	"strings"

	apiequality "k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apiserver/pkg/server"
	restclient "k8s.io/client-go/rest"

	"go.pinniped.dev/internal/plog"
)

// TODO unit test

type Middleware interface {
	Handle(ctx context.Context, rt RoundTrip)
}

// TODO consider adding methods for namespace, name, subresource filtering
type RoundTrip interface {
	Verb() Verb
	Resource() schema.GroupVersionResource
	Mutate(req func(obj Object)) // TODO add resp mutation support
}

type Object interface {
	runtime.Object // generic access to TypeMeta
	metav1.Object  // generic access to ObjectMeta
}

type Verb interface {
	verb() // private method to prevent creation of verbs outside this package
}

const (
	VerbCreate           verb = "create"
	VerbUpdate           verb = "update"
	VerbDelete           verb = "delete"
	VerbDeleteCollection verb = "deletecollection"
	VerbGet              verb = "get"
	VerbList             verb = "list"
	VerbWatch            verb = "watch"

	// TODO these are unsupported for now
	VerbPatch verb = "patch"
	VerbProxy verb = "proxy"
)

var _, _ Verb = VerbGet, verb("")

type verb string

func (verb) verb() {}

func configWithWrapper(config *restclient.Config, negotiatedSerializer runtime.NegotiatedSerializer, middlewares []Middleware) *restclient.Config {
	hostURL, apiPathPrefix, err := getHostAndAPIPathPrefix(config)
	if err != nil {
		plog.DebugErr("invalid rest config", err)
		return config // invalid input config, will fail existing client-go validation
	}

	// no need for any wrapping when we have no middleware to inject
	if len(middlewares) == 0 {
		return config
	}

	info, ok := runtime.SerializerInfoForMediaType(negotiatedSerializer.SupportedMediaTypes(), config.ContentType)
	if !ok {
		panic(fmt.Errorf("unknown content type: %s ", config.ContentType)) // static input, programmer error
	}
	regSerializer := info.Serializer // should perform no conversion
	streamSerializer := info.StreamSerializer

	_ = streamSerializer // TODO fix watch

	resolver := server.NewRequestInfoResolver(server.NewConfig(serializer.CodecFactory{}))

	f := func(rt http.RoundTripper) http.RoundTripper {
		return roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			reqInfo, err := resolver.NewRequestInfo(reqWithoutPrefix(req, hostURL, apiPathPrefix))
			if err != nil || !reqInfo.IsResourceRequest {
				return rt.RoundTrip(req) // we only handle kube resource requests
			}

			resource := schema.GroupVersionResource{
				Group:    reqInfo.APIGroup,
				Version:  reqInfo.APIVersion,
				Resource: reqInfo.Resource,
			}

			switch v := verb(reqInfo.Verb); v {
			case VerbCreate, VerbUpdate:
				middlewareReq := &request{
					verb:     v,
					resource: resource,
				}

				for _, middleware := range middlewares {
					middleware := middleware
					middleware.Handle(req.Context(), middlewareReq)
				}

				if len(middlewareReq.objFuncs) == 0 {
					return rt.RoundTrip(req) // no middleware wanted to mutate this request
				}

				if req.GetBody == nil {
					return nil, fmt.Errorf("unreadible body for %s request for %s", v, reqInfo.Resource) // this should never happen
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

				// attempt to decode with no defaults or into specified, i.e. defer to the decoder
				// this should result in the a straight decode with no conversion
				decodedObj, _, err := regSerializer.Decode(data, nil, nil)
				if err != nil {
					return nil, fmt.Errorf("body decode failed: %w", err)
				}

				obj, ok := decodedObj.(Object)
				if !ok { // TODO maybe this should error?
					return rt.RoundTrip(req) // ignore everything that has no object meta for now
				}

				origGVK := obj.GetObjectKind().GroupVersionKind()
				if origGVK.Empty() {
					return nil, fmt.Errorf("invalid empty orig GVK ")
				}

				origObj, ok := obj.DeepCopyObject().(Object)
				if !ok {
					return nil, fmt.Errorf("invalid deep copy semantics for %s", resource)
				}

				for _, objFunc := range middlewareReq.objFuncs {
					objFunc := objFunc
					objFunc(obj)
				}

				if apiequality.Semantic.DeepEqual(origObj, obj) {
					return rt.RoundTrip(req) // no middleware mutated the request
				}

				// we plan on making a new request so make sure to close the original request's body
				_ = req.Body.Close()

				newGVK := obj.GetObjectKind().GroupVersionKind()
				if newGVK.Empty() {
					return nil, fmt.Errorf("invalid empty new GVK ")
				}

				needsPathUpdate := origGVK != newGVK

				reqURL := req.URL
				if needsPathUpdate {
					if len(origGVK.Group) == 0 {
						return nil, fmt.Errorf("invalid attempt to change core group")
					}

					newURL := &url.URL{}
					*newURL = *reqURL

					// replace old GVK with new GVK
					apiRoot := path.Join(apiPathPrefix, "apis")
					oldPrefix := restclient.DefaultVersionedAPIPath(apiRoot, origGVK.GroupVersion())
					newPrefix := restclient.DefaultVersionedAPIPath(apiRoot, newGVK.GroupVersion())

					newURL.Path = path.Join(newPrefix, strings.TrimPrefix(newURL.Path, oldPrefix))

					reqURL = newURL
				}

				newData, err := runtime.Encode(regSerializer, obj)
				if err != nil {
					return nil, fmt.Errorf("new body encode failed: %w", err)
				}

				// simplest way to reuse the body creation logic
				newReqForBody, err := http.NewRequest(req.Method, reqURL.String(), bytes.NewReader(newData))
				if err != nil {
					return nil, fmt.Errorf("failed to create new req for body: %w", err) // this should never happen
				}

				// shallow copy because we want to preserve all the headers and such but not mutate the original request
				newReq := req.WithContext(req.Context())

				// replace the body and path with the new data
				newReq.URL = reqURL
				newReq.ContentLength = newReqForBody.ContentLength
				newReq.Body = newReqForBody.Body
				newReq.GetBody = newReqForBody.GetBody

				if !needsPathUpdate {
					return rt.RoundTrip(newReq) // we did not change the GVK, so we do not need to mess with the incoming data
				}

				resp, err := rt.RoundTrip(newReq)
				if err != nil {
					return nil, fmt.Errorf("request failed: %w", err)
				}

				switch {
				case resp.StatusCode == http.StatusSwitchingProtocols,
					resp.StatusCode < http.StatusOK || resp.StatusCode > http.StatusPartialContent:
					return resp, nil
				}

				respData, err := ioutil.ReadAll(resp.Body)
				if err != nil {
					return nil, fmt.Errorf("failed to read response body: %w", err)
				}

				_ = resp.Body.Close()

				contentType := resp.Header.Get("Content-Type")
				if len(contentType) == 0 {
					contentType = config.ContentType
				}
				mediaType, _, err := mime.ParseMediaType(contentType)
				if err != nil {
					return nil, fmt.Errorf("failed to parse content type: %w", err)
				}
				respInfo, ok := runtime.SerializerInfoForMediaType(negotiatedSerializer.SupportedMediaTypes(), mediaType)
				if !ok {
					return nil, fmt.Errorf("unable to find resp serialier for %s with content-type %s", reqInfo.Resource, mediaType)
				}

				// the body could be an API status, random trash or the actual object we want
				unknown := &runtime.Unknown{}
				_, _, _ = respInfo.Serializer.Decode(respData, nil, unknown) // we do not care about the return values

				fixedRespData := respData
				doesNotNeedGVKFix := len(unknown.Raw) == 0 || unknown.GroupVersionKind() != newGVK

				if !doesNotNeedGVKFix {
					gvkFixedData, err := restoreGVK(respInfo.Serializer, unknown, origGVK)
					if err != nil {
						return nil, fmt.Errorf("failed to restore GVK: %w", err)
					}
					fixedRespData = gvkFixedData
				}

				newResp := &http.Response{}
				*newResp = *resp

				newResp.Body = ioutil.NopCloser(bytes.NewBuffer(fixedRespData))
				return newResp, nil

			case VerbDelete, VerbDeleteCollection:
				// TODO
				fallthrough
			case VerbGet:
				// TODO
				fallthrough
			case VerbList:
				// TODO
				fallthrough
			case VerbWatch:
				// TODO
				fallthrough
			case VerbPatch, VerbProxy: // TODO for now we do not support patch or proxy interception
				fallthrough
			default:
				return rt.RoundTrip(req) // we only handle certain verbs
			}

			// TODO log newData at high loglevel similar to REST client
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

type request struct {
	verb     Verb
	resource schema.GroupVersionResource
	objFuncs []func(obj Object)
}

func (r *request) Verb() Verb {
	return r.verb
}

func (r *request) Resource() schema.GroupVersionResource {
	return r.resource
}

func (r *request) Mutate(req func(obj Object)) {
	r.objFuncs = append(r.objFuncs, req)
}

func getHostAndAPIPathPrefix(config *restclient.Config) (string, string, error) {
	hostURL, _, err := defaultServerUrlFor(config)
	if err != nil {
		return "", "", fmt.Errorf("failed to parse host URL from rest config: %w", err)
	}

	return hostURL.String(), hostURL.Path, nil
}

func reqWithoutPrefix(req *http.Request, hostURL, apiPathPrefix string) *http.Request {
	if len(apiPathPrefix) == 0 {
		return req
	}

	if !strings.HasSuffix(hostURL, "/") {
		hostURL += "/"
	}

	if !strings.HasPrefix(req.URL.String(), hostURL) {
		return req
	}

	if !strings.HasPrefix(apiPathPrefix, "/") {
		apiPathPrefix = "/" + apiPathPrefix
	}
	if !strings.HasSuffix(apiPathPrefix, "/") {
		apiPathPrefix += "/"
	}

	reqCopy := req.WithContext(req.Context())
	urlCopy := &url.URL{}
	*urlCopy = *reqCopy.URL
	urlCopy.Path = "/" + strings.TrimPrefix(urlCopy.Path, apiPathPrefix)
	reqCopy.URL = urlCopy

	return reqCopy
}

func restoreGVK(encoder runtime.Encoder, unknown *runtime.Unknown, gvk schema.GroupVersionKind) ([]byte, error) {
	typeMeta := runtime.TypeMeta{}
	typeMeta.APIVersion, typeMeta.Kind = gvk.ToAPIVersionAndKind()

	newUnknown := &runtime.Unknown{}
	*newUnknown = *unknown
	newUnknown.TypeMeta = typeMeta

	switch newUnknown.ContentType {
	case runtime.ContentTypeJSON:
		// json is messy if we want to avoid decoding the whole object
		keysOnly := map[string]json.RawMessage{}

		// get the keys.  this does not preserve order.
		if err := json.Unmarshal(newUnknown.Raw, &keysOnly); err != nil {
			return nil, fmt.Errorf("failed to unmarshall json keys: %w", err)
		}

		// turn the type meta into JSON bytes
		typeMetaBytes, err := json.Marshal(typeMeta)
		if err != nil {
			return nil, fmt.Errorf("failed to marshall type meta: %w", err)
		}

		// overwrite the type meta keys with the new data
		// TODO confirm this actually works
		if err := json.Unmarshal(typeMetaBytes, &keysOnly); err != nil {
			return nil, fmt.Errorf("failed to type meta keys: %w", err)
		}

		// marshall everything back to bytes
		newRaw, err := json.Marshal(keysOnly)
		if err != nil {
			return nil, fmt.Errorf("failed to marshall new raw: %w", err)
		}

		// we could just return the bytes but it feels weird to not use the encoder
		newUnknown.Raw = newRaw

	case runtime.ContentTypeProtobuf:
		// protobuf is easy because of the unknown wrapper
		// newUnknown.Raw already contains the correct data we need

	default:
		return nil, fmt.Errorf("unknown content type: %s", newUnknown.ContentType) // this should never happen
	}

	return runtime.Encode(encoder, newUnknown)
}
