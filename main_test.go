package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type jsonStruct struct {
	PublicKey       string `json:"public_key"`
	TokenService    string `json:"token-service"`
	AccountService  string `json:"account-service"`
	TokensNotBefore int    `json:"tokens-not-before"`
}

type AuthStripTestSuite struct {
	suite.Suite
	kc  *httptest.Server
	sut *httptest.Server
}

func (suite *AuthStripTestSuite) SetupSuite() {
	os.Setenv("HJ_PROXY_SSL", "true")
	os.Setenv("HJ_SSL", "false")
	os.Setenv("HJ_K8S", "None")
	os.Setenv("HJ_TOKEN", "testtoken")
	os.Setenv("HJ_KEYCLOAK", "None")
	os.Setenv("HJ_MODE", "authstrip")

	keyData, _ := ioutil.ReadFile("public.pem")
	jsonObj := jsonStruct{
		PublicKey:       string(keyData),
		TokenService:    "test",
		AccountService:  "test",
		TokensNotBefore: 0,
	}
	k8sServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.WriteHeader(http.StatusOK)
			jsonString, _ := json.Marshal(jsonObj)
			w.Write(jsonString)
		}
	}))
	suite.kc = k8sServer
	os.Setenv("HJ_KEYCLOAK", suite.kc.URL)
	fmt.Printf("+++%v", os.Getenv("HJ_KEYCLOAK"))

	suite.sut = httptest.NewServer(getMux())
}

func (suite *AuthStripTestSuite) TestBadAuthK8sPath() {
	resp, err := http.Get(fmt.Sprintf("%s/k8s/api", suite.sut.URL))

	assert.Nil(suite.T(), err, "error was not nil")
	assert.NotNil(suite.T(), resp, "response was nil")

	assert.Equal(suite.T(), 403, resp.StatusCode)
}

func (suite *AuthStripTestSuite) TestRegistrationPath() {
	resp, err := http.Get(fmt.Sprintf("%s/registration/api/v1/signup", suite.sut.URL))

	assert.Nil(suite.T(), err, "error was not nil")
	assert.NotNil(suite.T(), resp, "response was nil")

	assert.Equal(suite.T(), 200, resp.StatusCode)

	body, err := ioutil.ReadAll(resp.Body)
	assert.Nil(suite.T(), err, "read error not nil")
	assert.Equal(suite.T(), "{\"status\":{\"ready\":true}}", string(body))
}

func (suite *AuthStripTestSuite) TearDownSuite() {
	suite.kc.Close()
	suite.sut.Close()
}

func TestAuthStripTestSuite(t *testing.T) {
	suite.Run(t, new(AuthStripTestSuite))
}

type SimplePassthroughTestSuite struct {
	suite.Suite
	k8s *httptest.Server
	sut *httptest.Server
}

func (suite *SimplePassthroughTestSuite) SetupSuite() {
	os.Setenv("HJ_PROXY_SSL", "false")
	os.Setenv("HJ_SSL", "false")
	os.Setenv("HJ_TOKEN", "None")
	os.Setenv("HJ_KEYCLOAK", "None")
	os.Setenv("HJ_MODE", "simple")

	normalServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.WriteHeader(http.StatusOK)
		}
	}))
	suite.k8s = normalServer
	os.Setenv("HJ_K8S", suite.k8s.URL)
	os.Setenv("HJ_REG", suite.k8s.URL)

	suite.sut = httptest.NewServer(getMux())
}

func (suite *SimplePassthroughTestSuite) TestK8sPath() {
	resp, err := http.Get(fmt.Sprintf("%s/k8s/api", suite.sut.URL))

	assert.Nil(suite.T(), err, "error was not nil")
	assert.NotNil(suite.T(), resp, "response was nil")

	assert.Equal(suite.T(), 200, resp.StatusCode)
}

func (suite *SimplePassthroughTestSuite) TestRegistrationPath() {
	resp, err := http.Get(fmt.Sprintf("%s/registration/api/v1/signup", suite.sut.URL))

	assert.Nil(suite.T(), err, "error was not nil")
	assert.NotNil(suite.T(), resp, "response was nil")

	assert.Equal(suite.T(), 200, resp.StatusCode)

	body, err := ioutil.ReadAll(resp.Body)
	assert.Nil(suite.T(), err, "read error not nil")
	assert.Equal(suite.T(), "{\"status\":{\"ready\":true}}", string(body))
}

func (suite *SimplePassthroughTestSuite) TearDownSuite() {
	suite.k8s.Close()
	suite.sut.Close()
}

func TestExampleTestSuite(t *testing.T) {
	suite.Run(t, new(SimplePassthroughTestSuite))
}
