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

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apiserver/pkg/server"
	restclient "k8s.io/client-go/rest"
)

// TODO unit test

type Middleware interface {
	HandleRequest(ctx context.Context, req Request)
	HandleResponse(ctx context.Context, resp Response)
}

// TODO consider adding methods for namespace, name, subresource filtering
type Request interface {
	Verb() Verb
	MutateOutput(f func(obj metav1.Object))
}
type Response interface {
	MutateInput(f func(obj metav1.Object))
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
			reqInfo, err := resolver.NewRequestInfo(req)
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
				obj, _, err := regSerializer.Decode(data, nil, nil)
				if err != nil {
					return nil, fmt.Errorf("body decode failed: %w", err)
				}

				origGroup := obj.GetObjectKind().GroupVersionKind().Group

				accessor, err := meta.Accessor(obj)
				if err != nil {
					return rt.RoundTrip(req) // ignore everything that has no object meta for now
				}

				// we plan on making a new request so make sure to close the original request's body
				_ = req.Body.Close()

				middlewareReq := &request{
					verb: v,
					obj:  accessor,
				}

				for _, middleware := range middlewares {
					middleware.HandleRequest(req.Context(), middlewareReq)
				}

				newGroup := obj.GetObjectKind().GroupVersionKind().Group

				reqURL := req.URL
				if origGroup != newGroup {
					if len(origGroup) == 0 {
						return nil, fmt.Errorf("invalid attempt to change core group")
					}

					newURL := &url.URL{}
					*newURL = *reqURL

					// TODO replace old api group with new group in path

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

				for _, middleware := range middlewares {
					middleware.HandleResponse(req.Context(), middlewareResp)
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
	obj metav1.Object
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

func (r *request) MutateOutput(f func(obj metav1.Object)) {
	f(r.obj)
}

type response struct {
	obj metav1.Object
}

func (r *response) MutateInput(f func(obj metav1.Object)) {
	f(r.obj)
}
