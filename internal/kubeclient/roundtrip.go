// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package kubeclient

import (
	"bytes"
	"context"
	"encoding/json"
	stderrors "errors"
	"fmt"
	"io"
	"io/ioutil"
	"mime"
	"net/http"
	"net/url"
	"path"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/runtime/serializer/streaming"
	"k8s.io/apimachinery/pkg/util/net"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/watch"
	genericapirequest "k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/pkg/server"
	restclient "k8s.io/client-go/rest"
	restclientwatch "k8s.io/client-go/rest/watch"

	"go.pinniped.dev/internal/plog"
)

// TODO unit test

type Middleware interface {
	Handle(ctx context.Context, rt RoundTrip)
}

var _ Middleware = MiddlewareFunc(nil)

type MiddlewareFunc func(ctx context.Context, rt RoundTrip)

func (f MiddlewareFunc) Handle(ctx context.Context, rt RoundTrip) {
	f(ctx, rt)
}

// TODO consider adding methods for name based filtering
type RoundTrip interface {
	Verb() Verb
	Namespace() string // this is the only valid way to check namespace, Object.GetNamespace() will almost always be empty
	NamespaceScoped() bool
	Resource() schema.GroupVersionResource
	Subresource() string
	MutateRequest(f func(obj Object)) // TODO add response mutation support if we come up with a good use case
}

type Object interface {
	runtime.Object // generic access to TypeMeta
	metav1.Object  // generic access to ObjectMeta
}

type Verb interface {
	// TODO check if we need a String() method
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
	VerbPatch            verb = "patch"

	VerbProxy verb = "proxy" // TODO proxy unsupported for now
)

var _, _ Verb = VerbGet, verb("")

type verb string

func (verb) verb() {}

func configWithWrapper(config *restclient.Config, scheme *runtime.Scheme, negotiatedSerializer runtime.NegotiatedSerializer, middlewares []Middleware) *restclient.Config {
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

	resolver := server.NewRequestInfoResolver(server.NewConfig(serializer.CodecFactory{}))

	schemeRestMapperFunc := schemeRestMapper(scheme)

	f := func(rt http.RoundTripper) http.RoundTripper {
		return roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			reqInfo, err := resolver.NewRequestInfo(reqWithoutPrefix(req, hostURL, apiPathPrefix))
			if err != nil || !reqInfo.IsResourceRequest {
				return rt.RoundTrip(req) // we only handle kube resource requests
			}

			middlewareReq := &request{
				verb:      verb(reqInfo.Verb),
				namespace: reqInfo.Namespace,
				resource: schema.GroupVersionResource{
					Group:    reqInfo.APIGroup,
					Version:  reqInfo.APIVersion,
					Resource: reqInfo.Resource,
				},
				subresource: reqInfo.Subresource,
			}

			for _, middleware := range middlewares {
				middleware := middleware
				middleware.Handle(req.Context(), middlewareReq)
			}

			if len(middlewareReq.reqFuncs) == 0 {
				return rt.RoundTrip(req) // no middleware wanted to mutate this request
			}

			switch v := middlewareReq.Verb(); v {
			case VerbCreate, VerbUpdate:
				if req.GetBody == nil {
					return nil, fmt.Errorf("unreadible body for request: %#v", middlewareReq) // this should never happen
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
				decodedObj, err := runtime.Decode(regSerializer, data)
				if err != nil {
					return nil, fmt.Errorf("body decode failed: %w", err)
				}

				obj, ok := decodedObj.(Object)
				if !ok { // TODO maybe this should error?
					return rt.RoundTrip(req) // ignore everything that has no object meta for now
				}

				result, err := middlewareReq.mutate(obj)
				if err != nil {
					return nil, err
				}

				if !result.mutated {
					return rt.RoundTrip(req) // no middleware mutated the request
				}

				// we plan on making a new request so make sure to close the original request's body
				_ = req.Body.Close()

				reqURL, err := updatePathNewGVK(req.URL, result, apiPathPrefix, reqInfo)
				if err != nil {
					return nil, err
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
					return nil, fmt.Errorf("middleware request for %#v failed: %w", middlewareReq, err)
				}

				if !result.needsPathUpdate {
					return resp, nil // we did not change the GVK, so we do not need to mess with the incoming data
				}

				return handleResponseNewGVK(config, negotiatedSerializer, resp, middlewareReq, result)

			case VerbGet, VerbList, VerbDelete, VerbDeleteCollection, VerbPatch, VerbWatch:
				mapperGVK, ok := schemeRestMapperFunc(middlewareReq.Resource(), v)
				if !ok {
					return nil, fmt.Errorf("unable to determine GVK for middleware request %#v", middlewareReq)
				}

				// no need to do anything with object meta since we only support GVK changes
				obj := &metav1.PartialObjectMetadata{}
				obj.APIVersion, obj.Kind = mapperGVK.ToAPIVersionAndKind()

				result, err := middlewareReq.mutate(obj)
				if err != nil {
					return nil, err
				}

				if !result.mutated {
					return rt.RoundTrip(req) // no middleware mutated the request
				}

				metaIsZero := apiequality.Semantic.DeepEqual(obj.ObjectMeta, metav1.ObjectMeta{})
				if !result.needsPathUpdate || !metaIsZero {
					return nil, fmt.Errorf("invalid object meta mutation: %#v", middlewareReq)
				}

				reqURL, err := updatePathNewGVK(req.URL, result, apiPathPrefix, reqInfo)
				if err != nil {
					return nil, err
				}

				// shallow copy because we want to preserve all the headers and such but not mutate the original request
				newReq := req.WithContext(req.Context())

				// replace the body and path with the new data
				newReq.URL = reqURL

				resp, err := rt.RoundTrip(newReq)
				if err != nil {
					return nil, fmt.Errorf("middleware request for %#v failed: %w", middlewareReq, err)
				}

				switch v {
				case VerbDelete, VerbDeleteCollection:
					return resp, nil // we do not need to fix the response on delete

				case VerbWatch:
					return handleWatchResponseNewGVK(config, negotiatedSerializer, resp, middlewareReq, result)

				default:
					return handleResponseNewGVK(config, negotiatedSerializer, resp, middlewareReq, result)
				}

			case VerbProxy: // TODO for now we do not support proxy interception
				fallthrough

			default:
				return rt.RoundTrip(req) // we only handle certain verbs
			}

			// TODO log request and response body at high log level similar to REST client
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

var _ RoundTrip = &request{}

type request struct {
	verb        Verb
	namespace   string
	resource    schema.GroupVersionResource
	reqFuncs    []func(obj Object)
	subresource string
}

func (r *request) Verb() Verb {
	return r.verb
}

func (r *request) Namespace() string {
	return r.namespace
}

var namespaceGVR = corev1.SchemeGroupVersion.WithResource("namespaces")

func (r *request) NamespaceScoped() bool {
	if r.Resource() == namespaceGVR {
		return false // always consider namespaces to be cluster scoped
	}

	return len(r.Namespace()) != 0
}

func (r *request) Resource() schema.GroupVersionResource {
	return r.resource
}

func (r *request) Subresource() string {
	return r.subresource
}

func (r *request) MutateRequest(f func(obj Object)) {
	r.reqFuncs = append(r.reqFuncs, f)
}

type mutationResult struct {
	origGVK, newGVK          schema.GroupVersionKind
	needsPathUpdate, mutated bool
}

func (r *request) mutate(obj Object) (*mutationResult, error) {
	origGVK := obj.GetObjectKind().GroupVersionKind()
	if origGVK.Empty() {
		return nil, fmt.Errorf("invalid empty orig GVK for %T: %#v", obj, r)
	}

	origObj, ok := obj.DeepCopyObject().(Object)
	if !ok {
		return nil, fmt.Errorf("invalid deep copy semantics for %T: %#v", obj, r)
	}

	for _, reqFunc := range r.reqFuncs {
		reqFunc := reqFunc
		reqFunc(obj)
	}

	newGVK := obj.GetObjectKind().GroupVersionKind()
	if newGVK.Empty() {
		return nil, fmt.Errorf("invalid empty new GVK for %T: %#v", obj, r)
	}

	return &mutationResult{
		origGVK:         origGVK,
		newGVK:          newGVK,
		needsPathUpdate: origGVK != newGVK, // TODO support namespace and name changes?
		mutated:         !apiequality.Semantic.DeepEqual(origObj, obj),
	}, nil
}

func updatePathNewGVK(reqURL *url.URL, result *mutationResult, apiPathPrefix string, reqInfo *genericapirequest.RequestInfo) (*url.URL, error) {
	if !result.needsPathUpdate {
		return reqURL, nil
	}

	if len(result.origGVK.Group) == 0 {
		return nil, fmt.Errorf("invalid attempt to change core group") // TODO do we care?
	}

	newURL := &url.URL{}
	*newURL = *reqURL

	// replace old GVK with new GVK
	apiRoot := path.Join(apiPathPrefix, reqInfo.APIPrefix)
	oldPrefix := restclient.DefaultVersionedAPIPath(apiRoot, result.origGVK.GroupVersion())
	newPrefix := restclient.DefaultVersionedAPIPath(apiRoot, result.newGVK.GroupVersion())

	newURL.Path = path.Join(newPrefix, strings.TrimPrefix(newURL.Path, oldPrefix))

	return newURL, nil
}

func handleResponseNewGVK(
	config *restclient.Config,
	negotiatedSerializer runtime.NegotiatedSerializer,
	resp *http.Response,
	middlewareReq *request,
	result *mutationResult,
) (*http.Response, error) {
	// defer these status codes to client-go
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

	serializerInfo, err := getSerializerInfo(config, negotiatedSerializer, resp, middlewareReq)
	if err != nil {
		return nil, err
	}

	fixedRespData, err := maybeRestoreGVK(serializerInfo.Serializer, respData, result)
	if err != nil {
		return nil, fmt.Errorf("unable to restore GVK for %#v: %w", middlewareReq, err)
	}

	newResp := &http.Response{}
	*newResp = *resp

	newResp.Body = ioutil.NopCloser(bytes.NewBuffer(fixedRespData))
	return newResp, nil
}

func handleWatchResponseNewGVK(
	config *restclient.Config,
	negotiatedSerializer runtime.NegotiatedSerializer,
	resp *http.Response,
	middlewareReq *request,
	result *mutationResult,
) (*http.Response, error) {
	// defer non-success cases to client-go
	if resp.StatusCode != http.StatusOK {
		return resp, nil
	}

	var goRoutineStarted bool
	defer func() {
		if goRoutineStarted {
			return
		}
		_ = resp.Body.Close() // always close the body if we do not get to the point of starting our go routine
	}()

	serializerInfo, err := getSerializerInfo(config, negotiatedSerializer, resp, middlewareReq)
	if err != nil {
		return nil, err
	}

	newResp := &http.Response{}
	*newResp = *resp

	newBodyReader, newBodyWriter := io.Pipe()

	newResp.Body = newBodyReader // client-go is responsible for closing this reader

	goRoutineStarted = true
	go func() {
		defer utilruntime.HandleCrash()
		defer resp.Body.Close()
		defer newBodyWriter.Close()

		frameReader := serializerInfo.StreamSerializer.Framer.NewFrameReader(resp.Body)
		watchEventDecoder := streaming.NewDecoder(frameReader, serializerInfo.StreamSerializer.Serializer)
		sourceDecoder := restclientwatch.NewDecoder(watchEventDecoder, &passthroughDecoder{})
		defer sourceDecoder.Close()

		frameWriter := serializerInfo.StreamSerializer.Framer.NewFrameWriter(newBodyWriter)
		watchEventEncoder := streaming.NewEncoder(frameWriter, serializerInfo.StreamSerializer.Serializer)

		for {
			ok, err := sendWatchEvent(sourceDecoder, serializerInfo.Serializer, middlewareReq, result, watchEventEncoder)
			if err != nil {
				if stderrors.Is(err, io.ErrClosedPipe) {
					return // calling newBodyReader.Close() will send this to all newBodyWriter.Write()
				}

				// CloseWithError always returns nil
				// all newBodyReader.Read() will get this error
				_ = newBodyWriter.CloseWithError(err)

				return
			}

			if !ok {
				return
			}
		}
	}()

	return newResp, nil
}

func sendWatchEvent(sourceDecoder watch.Decoder, s runtime.Serializer, middlewareReq *request, result *mutationResult, watchEventEncoder streaming.Encoder) (bool, error) {
	// partially copied from watch.NewStreamWatcher.receive
	eventType, obj, err := sourceDecoder.Decode()
	if err != nil {
		switch {
		case stderrors.Is(err, io.EOF):
			// watch closed normally
		case stderrors.Is(err, io.ErrUnexpectedEOF):
			plog.InfoErr("Unexpected EOF during watch stream event decoding", err)
		case net.IsProbableEOF(err), net.IsTimeout(err):
			plog.TraceErr("Unable to decode an event from the watch stream", err)
		default:
			return false, fmt.Errorf("unexpected watch decode error for %#v: %w", middlewareReq, err)
		}
		return false, nil // all errors end watch
	}

	unknown, ok := obj.(*runtime.Unknown)
	if !ok || len(unknown.Raw) == 0 {
		return false, fmt.Errorf("unexpected decode type: %T", obj)
	}

	respData := unknown.Raw
	fixedRespData, err := maybeRestoreGVK(s, respData, result)
	if err != nil {
		return false, fmt.Errorf("unable to restore GVK for %#v: %w", middlewareReq, err)
	}

	event := &metav1.WatchEvent{
		Type:   string(eventType),
		Object: runtime.RawExtension{Raw: fixedRespData},
	}

	if err := watchEventEncoder.Encode(event); err != nil {
		return false, fmt.Errorf("failed to encode watch event for %#v: %w", middlewareReq, err)
	}

	return true, nil
}

func getSerializerInfo(config *restclient.Config, negotiatedSerializer runtime.NegotiatedSerializer, resp *http.Response, middlewareReq *request) (runtime.SerializerInfo, error) {
	contentType := resp.Header.Get("Content-Type")
	if len(contentType) == 0 {
		contentType = config.ContentType
	}

	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return runtime.SerializerInfo{}, fmt.Errorf("failed to parse content type for %#v: %w", middlewareReq, err)
	}

	respInfo, ok := runtime.SerializerInfoForMediaType(negotiatedSerializer.SupportedMediaTypes(), mediaType)
	if !ok || respInfo.Serializer == nil || respInfo.StreamSerializer == nil || respInfo.StreamSerializer.Serializer == nil || respInfo.StreamSerializer.Framer == nil {
		return runtime.SerializerInfo{}, fmt.Errorf("unable to find resp serialier for %#v with content-type %s", middlewareReq, mediaType)
	}

	return respInfo, nil
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

func maybeRestoreGVK(s runtime.Serializer, respData []byte, result *mutationResult) ([]byte, error) {
	// the body could be an API status, random trash or the actual object we want
	unknown := &runtime.Unknown{}
	_ = runtime.DecodeInto(s, respData, unknown) // we do not care about the error

	doesNotNeedGVKFix := len(unknown.Raw) == 0 || unknown.GroupVersionKind() != result.newGVK

	if doesNotNeedGVKFix {
		return respData, nil
	}

	return restoreGVK(s, unknown, result.origGVK)
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
