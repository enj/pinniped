// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package kubeclient

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"mime"
	"net/http"
	"net/url"
	"path"
	"strings"

	"go.pinniped.dev/internal/plog"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apiserver/pkg/server"
	restclient "k8s.io/client-go/rest"
)

// TODO unit test

type Middleware interface {
	HandleRequest(ctx context.Context, req Request) ResponseHandler
}

type ResponseHandler func(ctx context.Context, resp Response)

type Object interface {
	runtime.Object // generic access to TypeMeta
	metav1.Object  // generic access to ObjectMeta
}

// TODO consider adding methods for namespace, name, subresource filtering
type Request interface {
	Verb() Verb
	MutateOutput(f func(obj Object))
}
type Response interface {
	MutateInput(f func(obj Object))
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

			switch v := verb(reqInfo.Verb); v {
			case VerbCreate, VerbUpdate:
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
				if !ok {
					return rt.RoundTrip(req) // ignore everything that has no object meta for now
				}

				origGVK := obj.GetObjectKind().GroupVersionKind()

				// we plan on making a new request so make sure to close the original request's body
				_ = req.Body.Close()

				middlewareReq := &request{
					verb: v,
					obj:  obj,
				}

				var responseHandlers []ResponseHandler
				for _, middleware := range middlewares {
					middleware := middleware
					responseHandler := middleware.HandleRequest(req.Context(), middlewareReq)
					if responseHandler != nil {
						responseHandlers = append(responseHandlers, responseHandler)
					}
				}

				newGVK := obj.GetObjectKind().GroupVersionKind()

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

				// TODO handle GVK
				if needsPathUpdate {
					respData = respData
				}

				respObj, _, err := respInfo.Serializer.Decode(respData, nil, nil)
				if err != nil {
					return nil, fmt.Errorf("resp body decode failed: %w", err)
				}

				respAccessor, err := meta.Accessor(respObj)
				if err != nil {
					return nil, fmt.Errorf("failed to get meta for resp: %w", err)
				}

				middlewareResp := &response{
					obj: respAccessor,
				}

				for _, responseHandler := range responseHandlers {
					responseHandler := responseHandler
					responseHandler(req.Context(), middlewareResp)
				}

				newRespData, err := runtime.Encode(respInfo.Serializer, respObj)
				if err != nil {
					return nil, fmt.Errorf("new resp body encode failed: %w", err)
				}

				newResp := &http.Response{}
				*newResp = *resp

				newResp.Body = ioutil.NopCloser(bytes.NewBuffer(newRespData))
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
	verb Verb
	// group string
	obj Object
	// err error
}

func (r *request) Verb() Verb {
	return r.verb
}

// func (r *request) SetPath(resource schema.GroupVersionResource) {
// 	if len(r.group) != 0 {
// 		r.err = fmt.Errorf("set path called more than once: old=%s new=%s", r.group, resource)
// 		return
// 	}
//
// 	r.resource = resource
// }

func (r *request) MutateOutput(f func(obj Object)) {
	f(r.obj)
}

type response struct {
	obj Object
}

func (r *response) MutateInput(f func(obj Object)) {
	f(r.obj)
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
