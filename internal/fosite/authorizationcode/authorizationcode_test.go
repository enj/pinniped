package authorizationcode

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"math/rand"
	"net/url"
	"strings"
	"testing"
	"time"

	fuzz "github.com/google/gofuzz"
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/handler/openid"
	"github.com/stretchr/testify/require"
	"gopkg.in/square/go-jose.v2"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	coretesting "k8s.io/client-go/testing"
)

func TestAuthorizeCodeStorage(t *testing.T) {
	ctx := context.Background()

	const namespace = "test-ns"

	type mocker interface {
		AddReactor(verb, resource string, reaction coretesting.ReactionFunc)
		PrependReactor(verb, resource string, reaction coretesting.ReactionFunc)
		Tracker() coretesting.ObjectTracker
	}

	tests := []struct {
		name        string
		mocks       func(*testing.T, mocker)
		run         func(*testing.T, oauth2.AuthorizeCodeStorage) error
		wantActions []coretesting.Action
		wantSecrets []corev1.Secret
		wantErr     string
	}{
		{
			name:  "create, get, invalidate standard flow",
			mocks: nil,
			run: func(t *testing.T, storage oauth2.AuthorizeCodeStorage) error {
				request := &fosite.AuthorizeRequest{
					ResponseTypes: fosite.Arguments{"not-code"},
					RedirectURI: &url.URL{
						Scheme:      "",
						Opaque:      "weee",
						User:        &url.Userinfo{},
						Host:        "",
						Path:        "/callback",
						RawPath:     "",
						ForceQuery:  false,
						RawQuery:    "",
						Fragment:    "",
						RawFragment: "",
					},
					State:                "stated",
					HandledResponseTypes: fosite.Arguments{"not-type"},
					Request: fosite.Request{
						ID:          "abcd-1",
						RequestedAt: time.Time{},
						Client: &fosite.DefaultOpenIDConnectClient{
							DefaultClient: &fosite.DefaultClient{
								ID:            "pinny",
								Secret:        nil,
								RedirectURIs:  nil,
								GrantTypes:    nil,
								ResponseTypes: nil,
								Scopes:        nil,
								Audience:      nil,
								Public:        true,
							},
							JSONWebKeysURI:                    "where",
							JSONWebKeys:                       nil,
							TokenEndpointAuthMethod:           "something",
							RequestURIs:                       nil,
							RequestObjectSigningAlgorithm:     "",
							TokenEndpointAuthSigningAlgorithm: "",
						},
						RequestedScope: nil,
						GrantedScope:   nil,
						Form:           url.Values{"key": []string{"val"}},
						Session: &openid.DefaultSession{
							Claims:    nil,
							Headers:   nil,
							ExpiresAt: nil,
							Username:  "snorlax",
							Subject:   "panda",
						},
						RequestedAudience: nil,
						GrantedAudience:   nil,
					},
				}
				err := storage.CreateAuthorizeCodeSession(ctx, "fancy-signature", request)
				require.NoError(t, err)

				newRequest, err := storage.GetAuthorizeCodeSession(ctx, "fancy-signature", nil)
				require.NoError(t, err)
				require.Equal(t, request, newRequest)

				return storage.InvalidateAuthorizeCodeSession(ctx, "fancy-signature")
			},
			wantActions: nil,
			wantSecrets: nil,
			wantErr:     "",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			client := fake.NewSimpleClientset()
			if tt.mocks != nil {
				tt.mocks(t, client)
			}
			secrets := client.CoreV1().Secrets(namespace)
			storage := New(secrets)

			err := tt.run(t, storage)

			require.Equal(t, tt.wantErr, errString(err))
			require.Equal(t, tt.wantActions, client.Actions())

			actualSecrets, err := secrets.List(ctx, metav1.ListOptions{})
			require.NoError(t, err)
			require.Equal(t, tt.wantSecrets, actualSecrets.Items)
		})
	}
}

func errString(err error) string {
	if err == nil {
		return ""
	}

	return err.Error()
}

// TestFuzzAndJSONNewValidEmptyAuthorizeCodeSession asserts that we can correctly round trip our authorize code session.
// It will detect any changes to fosite.AuthorizeRequest and guarantees that all interface types have concrete implementations.
func TestFuzzAndJSONNewValidEmptyAuthorizeCodeSession(t *testing.T) {
	validSession := newValidEmptyAuthorizeCodeSession()

	// sanity check our valid session
	extractedRequest, err := validateAndExtractAuthorizeRequest(validSession.Request)
	require.NoError(t, err)
	require.Equal(t, validSession.Request, extractedRequest)

	// checked above
	defaultClient := validSession.Request.Request.Client.(*fosite.DefaultOpenIDConnectClient)
	defaultSession := validSession.Request.Request.Session.(*openid.DefaultSession)

	// makes it easier to use a raw string
	replacer := strings.NewReplacer("`", "a")
	randString := func(c fuzz.Continue) string {
		for {
			s := c.RandString()
			if len(s) == 0 {
				continue // skip empty string
			}
			return replacer.Replace(s)
		}
	}

	// deterministic fuzzing of fosite.AuthorizeRequest
	f := fuzz.New().RandSource(rand.NewSource(1)).NilChance(0).NumElements(1, 3).Funcs(
		// these functions guarantee that these are the only interface types we need to fill out
		// if fosite.AuthorizeRequest changes to add more, the fuzzer will panic
		func(fc *fosite.Client, c fuzz.Continue) {
			c.Fuzz(defaultClient)
			*fc = defaultClient
		},
		func(fs *fosite.Session, c fuzz.Continue) {
			c.Fuzz(defaultSession)
			*fs = defaultSession
		},

		// these types contain an interface{} that we need to handle
		// this is safe because we explicitly provide the openid.DefaultSession concrete type
		func(value *map[string]interface{}, c fuzz.Continue) {
			// cover all the JSON data types just in case
			*value = map[string]interface{}{
				randString(c): float64(c.Intn(1 << 32)),
				randString(c): map[string]interface{}{
					randString(c): []interface{}{float64(c.Intn(1 << 32))},
					randString(c): map[string]interface{}{
						randString(c): nil,
						randString(c): map[string]interface{}{
							randString(c): c.RandBool(),
						},
					},
				},
			}
		},
		// JWK contains an interface{} Key that we need to handle
		// this is safe because JWK explicitly implements JSON marshalling and unmarshalling
		func(jwk *jose.JSONWebKey, c fuzz.Continue) {
			key, _, err := ed25519.GenerateKey(c)
			require.NoError(t, err)
			jwk.Key = key

			// set these fields to make the .JSONEq comparison work
			jwk.Certificates = []*x509.Certificate{}
			jwk.CertificatesURL = &url.URL{}
			jwk.CertificateThumbprintSHA1 = []byte{}
			jwk.CertificateThumbprintSHA256 = []byte{}
		},

		// set this to make the .JSONEq comparison work
		// this is safe because Time explicitly implements JSON marshalling and unmarshalling
		func(tp *time.Time, c fuzz.Continue) {
			*tp = time.Unix(c.Int63n(1<<32), c.Int63n(1<<32))
		},

		// make random strings that do not contain any ` characters
		func(s *string, c fuzz.Continue) {
			*s = randString(c)
		},
		// handle string type alias
		func(s *fosite.TokenType, c fuzz.Continue) {
			*s = fosite.TokenType(randString(c))
		},
		// handle string type alias
		func(s *fosite.Arguments, c fuzz.Continue) {
			n := c.Intn(3) + 1 // 1 to 3 items
			arguments := make(fosite.Arguments, n)
			for i := range arguments {
				arguments[i] = randString(c)
			}
			*s = arguments
		},
	)

	f.Fuzz(validSession)

	const name = "fuzz" // value is irrelevant
	ctx := context.Background()
	secrets := fake.NewSimpleClientset().CoreV1().Secrets(name)
	storage := New(secrets)

	// issue a create using the fuzzed request to confirm that marshalling works
	err = storage.CreateAuthorizeCodeSession(ctx, name, validSession.Request)
	require.NoError(t, err)

	// retrieve a copy of the fuzzed request from storage to confirm that unmarshalling works
	newRequest, err := storage.GetAuthorizeCodeSession(ctx, name, nil)
	require.NoError(t, err)

	// the fuzzed request and the copy from storage should be exactly the same
	require.Equal(t, validSession.Request, newRequest)

	secretList, err := secrets.List(ctx, metav1.ListOptions{})
	require.NoError(t, err)
	require.Len(t, secretList.Items, 1)
	authorizeCodeSessionJSONFromStorage := string(secretList.Items[0].Data["pinniped-storage-data"])

	// set these to match CreateAuthorizeCodeSession so that .JSONEq works
	validSession.Active = true
	validSession.Version = "1"

	validSessionJSONBytes, err := json.MarshalIndent(validSession, "", "\t")
	require.NoError(t, err)
	authorizeCodeSessionJSONFromFuzzing := string(validSessionJSONBytes)

	// the fuzzed session and storage session should have identical JSON
	require.JSONEq(t, authorizeCodeSessionJSONFromFuzzing, authorizeCodeSessionJSONFromStorage)

	// while the fuzzer will panic if AuthorizeRequest changes in a way that cannot be fuzzed,
	// if it adds a new field that can be fuzzed, this check will fail
	// thus if AuthorizeRequest changes, we will detect it here (though we could possibly miss an omitempty field)
	require.Equal(t, expectedAuthorizeCodeSessionJSONFromFuzzing, authorizeCodeSessionJSONFromFuzzing)
}

const expectedAuthorizeCodeSessionJSONFromFuzzing = `{
	"active": true,
	"request": {
		"responseTypes": [
			"¥Îʒ襧.ɕ7崛瀇莒AȒ[ɠ牐7#$ɭ",
			".5ȿEǈ9ûF済(D疻翋膗",
			"螤Yɫüeɯ紤邥翔勋\\RBʒ;-"
		],
		"redirectUri": {
			"Scheme": "ħesƻU赒M喦_ģ",
			"Opaque": "Ġ/_章Ņ缘T蝟Ǌ儱礹燃ɢ",
			"User": {},
			"Host": "ȳ4螘Wo",
			"Path": "}i{",
			"RawPath": "5ǅa丝eF0eė鱊hǒx蔼Q",
			"ForceQuery": true,
			"RawQuery": "熤1bbWV",
			"Fragment": "ȋc剠鏯ɽÿ¸",
			"RawFragment": "qƤ"
		},
		"state": "@n,x竘Şǥ嗾稀'ã击漰怼禝穞梠Ǫs",
		"handledResponseTypes": [
			"m\"e尚鬞ƻɼ抹d誉y鿜Ķ"
		],
		"id": "ō澩ć|3U2Ǜl霨ǦǵpƉ",
		"requestedAt": "1989-11-05T17:02:31.105295894-05:00",
		"client": {
			"id": "[:c顎疻紵D",
			"client_secret": "mQ==",
			"redirect_uris": [
				"恣S@T嵇ǇV,Æ櫔袆鋹奘菲",
				"ãƻʚ肈ą8O+a駣Ʉɼk瘸'鴵y"
			],
			"grant_types": [
				".湆ê\"唐",
				"曎餄FxD溪躲珫ÈşɜȨû臓嬣\"ǃŤz"
			],
			"response_types": [
				"Ņʘʟ車sʊ儓JǐŪɺǣy|耑ʄ"
			],
			"scopes": [
				"Ą",
				"萙Į(潶饏熞ĝƌĆ1",
				"əȤ4Į筦p煖鵄$睱奐耡q"
			],
			"audience": [
				"Ʃǣ鿫/Ò敫ƤV"
			],
			"public": true,
			"jwks_uri": "ȩđ[嬧鱒Ȁ彆媚杨嶒ĤG",
			"jwks": {
				"keys": [
					{
						"kty": "OKP",
						"crv": "Ed25519",
						"x": "JmA-6KpjzqKu0lq9OiB6ORL4s2UzBFPsE1hm6vESeXM",
						"x5u": {
							"Scheme": "",
							"Opaque": "",
							"User": null,
							"Host": "",
							"Path": "",
							"RawPath": "",
							"ForceQuery": false,
							"RawQuery": "",
							"Fragment": "",
							"RawFragment": ""
						}
					},
					{
						"kty": "OKP",
						"crv": "Ed25519",
						"x": "LbRC1_3HEe5o7Japk9jFp3_7Ou7Gi2gpqrVrIi0eLDQ",
						"x5u": {
							"Scheme": "",
							"Opaque": "",
							"User": null,
							"Host": "",
							"Path": "",
							"RawPath": "",
							"ForceQuery": false,
							"RawQuery": "",
							"Fragment": "",
							"RawFragment": ""
						}
					},
					{
						"kty": "OKP",
						"crv": "Ed25519",
						"x": "Ovk4DF8Yn3mkULuTqnlGJxFnKGu9EL6Xcf2Nql9lK3c",
						"x5u": {
							"Scheme": "",
							"Opaque": "",
							"User": null,
							"Host": "",
							"Path": "",
							"RawPath": "",
							"ForceQuery": false,
							"RawQuery": "",
							"Fragment": "",
							"RawFragment": ""
						}
					}
				]
			},
			"token_endpoint_auth_method": "\u0026(K鵢Kj ŏ9Q韉Ķ%嶑輫ǘ(",
			"request_uris": [
				":",
				"6ě#嫀^xz Ū胧r"
			],
			"request_object_signing_alg": "^¡!犃ĹĐJí¿ō擫ų懫砰¿",
			"token_endpoint_auth_signing_alg": "ƈŮå"
		},
		"scopes": [
			"阃.Ù頀ʌGa皶竇瞍涘¹",
			"ȽŮ切衖庀ŰŒ矠",
			"楓)馻řĝǕ菸Tĕ1伞柲\u003c\"ʗȆ\\雤"
		],
		"grantedScopes": [
			"ơ鮫R嫁ɍUƞ9+u!Ȱ",
			"}Ă岜"
		],
		"form": {
			"旸Ť/Õ薝隧;綡,鼞纂=": [
				"[滮]憀",
				"3\u003eÙœ蓄UK嗤眇疟Țƒ1v¸KĶ"
			]
		},
		"session": {
			"Claims": {
				"JTI": "};Ų斻遟a衪荖舃",
				"Issuer": "芠顋敀拲h蝺$!",
				"Subject": "}j%(=ſ氆]垲莲顇",
				"Audience": [
					"彑V\\廳蟕Țǡ蔯ʠ浵Ī龉磈螖畭5",
					"渇Ȯʕc"
				],
				"Nonce": "Ǖ=rlƆ褡{ǏS",
				"ExpiresAt": "1975-11-17T09:21:34.205609651-05:00",
				"IssuedAt": "2104-07-03T11:40:03.66710966-04:00",
				"RequestedAt": "2031-05-18T01:14:19.449350555-04:00",
				"AuthTime": "2018-01-27T02:55:06.056862114-05:00",
				"AccessTokenHash": "鹰肁躧",
				"AuthenticationContextClassReference": "}Ɇ",
				"AuthenticationMethodsReference": "DQh:uȣ",
				"CodeHash": "ɘȏıȒ諃龟",
				"Extra": {
					"a": {
						"^i臏f恡ƨ彮": {
							"DĘ敨ýÏʥZq7烱藌\\": null,
							"V": {
								"őŧQĝ微'X焌襱ǭɕņ殥!_n": false
							}
						},
						"Ż猁": [
							1706822246
						]
					},
					"Ò椪)ɫqň2搞Ŀ高摠鲒鿮禗O": 1233332227
				}
			},
			"Headers": {
				"Extra": {
					"?戋璖$9\u0026": {
						"µcɕ餦ÑEǰ哤癨浦浏1R": [
							3761201123
						],
						"頓ć§蚲6rǦ\u003cqċ": {
							"Łʀ§ȏœɽǲ斡冭ȸěaʜD捛?½ʀ+": null,
							"ɒúĲ誠ƉyÖ.峷1藍殙菥趏": {
								"jHȬȆ#)\u003cX": true
							}
						}
					},
					"U": 1354158262
				}
			},
			"ExpiresAt": {
				"\"嘬ȹĹaó剺撱Ȱ": "1985-09-09T00:35:40.533197189-04:00",
				"ʆ\u003e": "1998-08-07T01:37:11.759718906-04:00",
				"柏ʒ鴙*鸆偡Ȓ肯Ûx": "2036-12-19T01:36:14.414805124-05:00"
			},
			"Username": "qmʎaðƠ绗ʢ緦Hū",
			"Subject": "屾Ê窢ɋ鄊qɠ谫ǯǵƕ牀1鞊\\ȹ)"
		},
		"requestedAudience": [
			"鉍商OɄƣ圔,xĪɏV鵅砍"
		],
		"grantedAudience": [
			"C笜嚯\u003cǐšɚĀĥʋ6鉅\\þc涎漄Ɨ腼"
		]
	},
	"version": "1"
}`
