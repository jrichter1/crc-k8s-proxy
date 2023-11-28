package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
)

type Realm struct {
	Realm     string `json:"realm"`
	PublicKey string `json:"public_key"`
}

type ManglerConfig struct {
	K8SURL          url.URL
	RegistrationURL url.URL
	Bearer          string
	PublicKey       string
	Validator       *CRCAuthValidator
}

type AuthMangler struct {
	URL    *url.URL
	Config *ManglerConfig
	Log    *log.Logger
}

type SimpleMangler struct {
	URL    *url.URL
	Config *ManglerConfig
	Log    *log.Logger
}

type ManglerObject interface {
	modifier(request *http.Request)
}

var authError = "X-Auth-Error"

type roundTripFilter struct {
	parent http.RoundTripper
	logger *log.Logger
}

func (rtf *roundTripFilter) RoundTrip(r *http.Request) (*http.Response, error) {
	if err, ok := r.Header[authError]; ok {
		return &http.Response{
			StatusCode: 403,
		}, errors.New(strings.Join(err, ","))
	}
	resp, err := rtf.parent.RoundTrip(r)
	if resp != nil {
		logger.Println(r.Method, r.URL.Path, r.RemoteAddr, r.UserAgent(), resp.StatusCode)
	}
	if err != nil {
		logger.Println(err)
	}
	return resp, err
}

func NewSimpleMangler(k8sURL url.URL, registrationURL url.URL, logger *log.Logger) (ManglerObject, error) {
	m := &SimpleMangler{
		Config: &ManglerConfig{
			K8SURL:          k8sURL,
			RegistrationURL: registrationURL,
		},
		Log: logger,
	}
	return m, nil
}

func (m *SimpleMangler) modifier(request *http.Request) {
	if strings.HasPrefix(request.URL.Path, "/wss/k8s") {
		path := strings.Replace(request.URL.Path, "/wss/k8s", "", 1)
		request.URL.Path = path
	}
	if strings.HasPrefix(request.URL.Path, "/api/k8s/registration") {
		request.URL.Host = m.Config.RegistrationURL.Host
		request.URL.Scheme = m.Config.RegistrationURL.Scheme
		request.Host = m.Config.RegistrationURL.Host
		request.URL.Path = strings.Split(request.URL.Path, "/k8s/registration")[1]
		request.Header.Set("Origin", fmt.Sprintf("%s://%s", m.Config.RegistrationURL.Scheme, m.Config.RegistrationURL.Host))
	} else {
		request.URL.Host = m.Config.K8SURL.Host
		request.URL.Scheme = m.Config.K8SURL.Scheme
		request.Host = m.Config.K8SURL.Host
		request.Header.Set("Origin", fmt.Sprintf("%s://%s", m.Config.K8SURL.Scheme, m.Config.K8SURL.Host))
	}
}

func NewAuthMangler(k8sURL url.URL, registrationURL url.URL, logger *log.Logger) (ManglerObject, error) {

	token := os.Getenv("HJ_TOKEN")
	if token == "" {
		panic("HJ_TOKEN env var missing")
	}

	keycloak := os.Getenv("HJ_KEYCLOAK")
	if keycloak == "" {
		panic("HJ_KEYCLOAK env var missing")
	}

	validator, err := NewCRCAuthValidator(&ValidatorConfig{
		KeycloakURL: keycloak,
	}, logger)

	if err != nil {
		return nil, err
	}

	m := &AuthMangler{
		Config: &ManglerConfig{
			K8SURL:          k8sURL,
			RegistrationURL: registrationURL,
			Bearer:          token,
			Validator:       validator,
		},
		Log: logger,
	}
	return m, nil
}

func (m *AuthMangler) modifier(request *http.Request) {
	err := m.Config.Validator.ProcessRequest(request)
	if err != nil {
		request.Header.Add(authError, "bad auth error")
	}
	if strings.HasPrefix(request.URL.Path, "/api/k8s/registration") {
		request.URL.Host = m.Config.RegistrationURL.Host
		request.URL.Scheme = m.Config.RegistrationURL.Scheme
		request.Host = m.Config.RegistrationURL.Host
		request.URL.Path = strings.Split(request.URL.Path, "/k8s/registration")[1]
	} else {
		request.URL.Host = m.Config.K8SURL.Host
		request.URL.Scheme = m.Config.K8SURL.Scheme
		request.Host = m.Config.K8SURL.Host
	}
	request.Header.Del("Authorization")
	request.Header.Add("Authorization", fmt.Sprintf("Bearer %s", m.Config.Bearer))
}

var logger *log.Logger

func init() {
	logger = log.New(os.Stdout, "", log.LstdFlags)
}

func proxyErrorHandler(w http.ResponseWriter, r *http.Request, err error) {
	if err.Error() == "bad auth error" {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("auth was denied by server"))
	} else {
		w.WriteHeader(http.StatusBadGateway)
		w.Write([]byte("unidentified error"))
	}
}

func getMux() *http.ServeMux {
	k8sURL := os.Getenv("HJ_K8S")
	if k8sURL == "" {
		panic("HJ_K8s env var missing")
	}

	registrationURL := os.Getenv("HJ_REG")
	if registrationURL == "" {
		panic("HJ_REG env var missing")
	}

	mode := os.Getenv("HJ_MODE")
	if mode == "" {
		mode = "simple"
	}

	logger.Printf("Mode: %s\n", mode)

	var proxySSL bool
	proxyString := os.Getenv("HJ_PROXY_SSL")
	if proxyString == "" {
		proxyString = "true"
	}

	proxySSL, err := strconv.ParseBool(proxyString)
	if err != nil {
		panic(err)
	}

	regURL, err := url.Parse(registrationURL)
	if err != nil {
		panic(err)
	}

	rpURL, err := url.Parse(k8sURL)
	if err != nil {
		panic(err)
	}
	logger.Printf("Forwarding to: %s\n", k8sURL)
	logger.Printf("Proxy SSL mode on: %t\n", proxySSL)

	var mangler ManglerObject

	if mode == "simple" {
		mangler, err = NewSimpleMangler(
			*rpURL,
			*regURL,
			logger,
		)
	} else {
		mangler, err = NewAuthMangler(
			*rpURL,
			*regURL,
			logger,
		)
	}

	if err != nil {
		panic(fmt.Sprintf("encountered error loading: %s", err))
	}

	var transport http.RoundTripper
	if proxySSL {
		transport = &roundTripFilter{parent: http.DefaultTransport, logger: logger}
	} else {
		transport = &roundTripFilter{
			parent: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true},
			},
			logger: logger,
		}
	}

	proxy := httputil.ReverseProxy{
		Director:     mangler.modifier,
		Transport:    transport,
		ErrorLog:     logger,
		ErrorHandler: proxyErrorHandler,
	}

	mux := http.NewServeMux()

	mux.Handle("/", &proxy)

	return mux
}

func main() {

	var ssl bool
	sslString := os.Getenv("HJ_SSL")
	if sslString == "" {
		sslString = "true"
	}

	ssl, err := strconv.ParseBool(sslString)
	if err != nil {
		panic(err)
	}

	serve := os.Getenv("HJ_SERVE")
	if serve == "" {
		serve = ":8000"
	}

	logger.Println("Server is starting...")
	logger.Printf("Listening on: %s\n", serve)
	logger.Printf("SSL mode on: %t\n", ssl)

	mux := getMux()

	if ssl {
		err = http.ListenAndServeTLS(serve, "/tmp/certs/tls.crt", "/tmp/certs/tls.key", mux)
		if err != nil {
			fmt.Printf("%s", err)
		}
	} else {
		err = http.ListenAndServe(serve, mux)
		if err != nil {
			fmt.Printf("%s", err)
		}
	}
}

func logging(logger *log.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				logger.Println(r.Method, r.URL.Path, r.RemoteAddr, r.UserAgent())
			}()
			next.ServeHTTP(w, r)
		})
	}
}
