package pandora

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

// 创建一个cookie jar
var jar, _ = cookiejar.New(nil)

type Auth0 struct {
	sessionToken string
	email        string
	password     string
	useCache     bool
	mfa          string
	session      *http.Client
	//reqKwargs    map[string]interface{}
	accessToken  string
	refreshToken string
	expires      time.Time
	userAgent    string
	apiPrefix    string
}

func NewAuth0(email, password, proxy string, useCache bool, mfa string) *Auth0 {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		Proxy:           http.ProxyFromEnvironment,
	}

	if proxy != "" {
		proxyURL, _ := url.Parse(proxy)
		tr.Proxy = http.ProxyURL(proxyURL)
	}

	apiPrefix := "https://ai.fakeopen.com"
	if os.Getenv("CHATGPT_API_PREFIX") != "" {
		apiPrefix = os.Getenv("CHATGPT_API_PREFIX")
	}

	return &Auth0{
		sessionToken: "",
		email:        email,
		password:     password,
		useCache:     useCache,
		mfa:          mfa,
		session: &http.Client{
			Timeout:   time.Second * 100,
			Transport: tr,
			Jar:       jar,
			//CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// 禁用跟随301跳转
			//	return http.ErrUseLastResponse
			//},
		},
		accessToken: "",
		expires:     time.Time{},
		userAgent:   "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36",
		apiPrefix:   apiPrefix,
	}
}

func (a *Auth0) checkEmail(email string) bool {
	re := regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b`)
	return re.MatchString(email)
}

func (a *Auth0) Auth(loginLocal bool) (string, error) {
	if a.useCache && a.accessToken != "" && a.expires.After(time.Now()) {
		return a.accessToken, nil
	}

	if !a.checkEmail(a.email) || a.password == "" {
		return "", errors.New("invalid email or password")
	}

	if loginLocal {
		return a.partTwo()
	}

	return a.getAccessTokenProxy()
}

func (a *Auth0) partTwo() (string, error) {
	codeVerifier, _ := GenerateCodeVerifier()
	codeChallenge := GenerateCodeChallenge(codeVerifier)

	newUrl := "https://auth0.openai.com/authorize?client_id=pdlLIX2Y72MIl2rhLhTE9VV9bN905kBh&audience=https%3A%2F%2Fapi.openai.com%2Fv1&redirect_uri=com.openai.chat%3A%2F%2Fauth0.openai.com%2Fios%2Fcom.openai.chat%2Fcallback&scope=openid%20email%20profile%20offline_access%20model.request%20model.read%20organization.read%20offline&response_type=code&code_challenge=HlLnX9QkMGL0gGRBoyjtXtWcuIc9_t_CTNyNX8dLahk&code_challenge_method=S256&prompt=login"
	newUrl = strings.Replace(newUrl, "code_challenge=HlLnX9QkMGL0gGRBoyjtXtWcuIc9_t_CTNyNX8dLahk", "code_challenge="+codeChallenge, 1)
	return a.partThree(codeVerifier, newUrl)
}

func (a *Auth0) partThree(codeVerifier, urlStr string) (string, error) {
	req, err := http.NewRequest(http.MethodGet, urlStr, nil)
	if err != nil {
		return "", fmt.Errorf("create request_partThree error: %s", err)
	}
	req.Header.Set("Referer", "https://ios.chat.openai.com/")
	req.Header.Set("User-Agent", a.userAgent)
	resp, err := a.session.Do(req)
	if err != nil {
		return "", fmt.Errorf("do request_partThree error: %s", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		urlParams, _ := url.ParseQuery(resp.Request.URL.RawQuery)
		state := urlParams.Get("state")
		if state == "" {
			return "", errors.New("state parameter not found")
		}
		return a.partFour(codeVerifier, state)
	}

	return "", errors.New("error requesting login url")
}

func (a *Auth0) partFour(codeVerifier, state string) (string, error) {
	urlStr := "https://auth0.openai.com/u/login/identifier?state=" + state

	// POST 用户名数据
	// 构建请求体数据
	formData := url.Values{}
	formData.Set("state", state)
	formData.Set("username", a.email)
	formData.Set("js-available", "true")
	formData.Set("webauthn-available", "true")
	formData.Set("is-brave", "false")
	formData.Set("webauthn-platform-available", "false")
	formData.Set("action", "default")
	body := strings.NewReader(formData.Encode())

	req, err := http.NewRequest("POST", urlStr, body)
	if err != nil {
		return "", fmt.Errorf("error creating request: %v", err)
	}
	req.Header.Set("User-Agent", a.userAgent)
	req.Header.Set("Referer", urlStr)
	req.Header.Set("Origin", "https://auth0.openai.com")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	//set not allow redirect
	a.session.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	resp, err := a.session.Do(req)
	if err != nil {
		return "", fmt.Errorf("error checking email: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusFound {
		return a.partFive(codeVerifier, state)
	}

	return "", errors.New("error checking email")
}

func (a *Auth0) partFive(codeVerifier, state string) (string, error) {
	urlStr := "https://auth0.openai.com/u/login/password?state=" + state

	// POST用户名与密码
	// 构建请求体数据
	formData := url.Values{}
	formData.Set("state", state)
	formData.Set("username", a.email)
	formData.Set("password", a.password)
	formData.Set("action", "default")
	body := strings.NewReader(formData.Encode())

	req, err := http.NewRequest("POST", urlStr, body)
	if err != nil {
		return "", fmt.Errorf("error creating request: %v", err)
	}
	req.Header.Set("User-Agent", a.userAgent)
	req.Header.Set("Origin", "https://auth0.openai.com")
	req.Header.Set("Referer", urlStr)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	a.session.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	resp, err := a.session.Do(req)
	if err != nil {
		return "", fmt.Errorf("error logging in: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusFound {
		location := resp.Header.Get("Location")
		if !strings.HasPrefix(location, "/authorize/resume?") {
			return "", errors.New("login callback failed")
		}
		return a.partSix(codeVerifier, location, urlStr)
	} else if resp.StatusCode == http.StatusBadRequest {
		return "", errors.New("wrong email or password")
	}

	return "", errors.New("error logging in")
}

func (a *Auth0) partSix(codeVerifier, location, urlStr string) (string, error) {
	newUrl := "https://auth0.openai.com" + location

	req, err := http.NewRequest("GET", newUrl, nil)
	if err != nil {
		return "", fmt.Errorf("error creating request: %v", err)
	}
	req.Header.Set("User-Agent", a.userAgent)
	req.Header.Set("Referer", urlStr)

	a.session.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	resp, err := a.session.Do(req)
	if err != nil {
		return "", fmt.Errorf("error logging in: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusFound {
		location := resp.Header.Get("Location")

		if strings.HasPrefix(location, "/u/mfa-otp-challenge?") {
			if a.mfa == "" {
				return "", errors.New("MFA required")
			}
			return a.partSeven(codeVerifier, location)
		}

		if !strings.HasPrefix(location, "com.openai.chat://auth0.openai.com/ios/com.openai.chat/callback?") {
			return "", errors.New("login callback failed")
		}

		return a.getAccessToken(codeVerifier, resp.Header.Get("Location"))
	}
	return "", errors.New("error logging in")
}

func (a *Auth0) partSeven(codeVerifier, location string) (string, error) {
	urlStr := "https://auth0.openai.com" + location

	urlParams, _ := url.ParseQuery(urlStr)
	state := urlParams.Get("state")

	// 构建请求体数据
	formData := url.Values{}
	formData.Set("state", state)
	formData.Set("code", a.mfa)
	formData.Set("action", "default")
	body := strings.NewReader(formData.Encode())

	req, err := http.NewRequest("POST", urlStr, body)
	if err != nil {
		return "", fmt.Errorf("error creating request: %v", err)
	}
	req.Header.Set("User-Agent", a.userAgent)
	req.Header.Set("Origin", "https://auth0.openai.com")
	req.Header.Set("Referer", urlStr)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	a.session.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	resp, err := a.session.Do(req)
	if err != nil {
		return "", fmt.Errorf("error MFA: %s", err.Error())
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusFound {
		location := resp.Header.Get("Location")
		if !strings.HasPrefix(location, "/authorize/resume?") {
			return "", errors.New("MFA failed")
		}

		return a.partSix(codeVerifier, location, urlStr)
	}

	if resp.StatusCode == http.StatusBadRequest {
		return "", errors.New("wrong MFA code")
	}

	return "", errors.New("error logging in")
}

func (a *Auth0) getAccessToken(codeVerifier, callbackURL string) (string, error) {
	parsedURL, err := url.Parse(callbackURL)
	if err != nil {
		return "", fmt.Errorf("error parsing callback url: %v", err)
	}
	urlParams := parsedURL.Query()

	if errorParam := urlParams.Get("error"); errorParam != "" {
		errorDesc := urlParams.Get("error_description")
		return "", fmt.Errorf("%s: %s", errorParam, errorDesc)
	}

	code := urlParams.Get("code")
	if code == "" {
		return "", fmt.Errorf("error getting code from callback url: %v", callbackURL)
	}

	urlStr := "https://auth0.openai.com/oauth/token"

	// 构建请求体数据
	formData := url.Values{}
	formData.Set("redirect_uri", "com.openai.chat://auth0.openai.com/ios/com.openai.chat/callback")
	formData.Set("grant_type", "authorization_code")
	formData.Set("client_id", "pdlLIX2Y72MIl2rhLhTE9VV9bN905kBh")
	formData.Set("code", code)
	formData.Set("code_verifier", codeVerifier)
	body := strings.NewReader(formData.Encode())

	req, err := http.NewRequest("POST", urlStr, body)
	if err != nil {
		return "", fmt.Errorf("error creating request: %v", err)
	}
	req.Header.Set("User-Agent", a.userAgent)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	a.session.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	resp, err := a.session.Do(req)
	if err != nil {
		return "", fmt.Errorf("error getting access token: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		var response struct {
			AccessToken  string `json:"access_token"`
			RefreshToken string `json:"refresh_token"`
			ExpiresIn    int    `json:"expires_in"`
		}
		err := json.NewDecoder(resp.Body).Decode(&response)
		if err != nil {
			return "", fmt.Errorf("error decoding response: %v", err)
		}

		if response.AccessToken == "" {
			return "", errors.New("get access token failed, maybe you need a proxy")
		}

		a.accessToken = response.AccessToken
		a.refreshToken = response.RefreshToken
		expiresAt := time.Now().UTC().Add(time.Second * time.Duration(response.ExpiresIn)).Add(-5 * time.Minute)
		a.expires = expiresAt
		return a.accessToken, nil
	}

	return "", fmt.Errorf("error getting access token: %s", resp.Status)
}

// TODO can't use, report 500 error
func (a *Auth0) getAccessTokenProxy() (string, error) {
	urlStr := fmt.Sprintf("%s/api/auth/login", a.apiPrefix)

	// POST用户名与密码
	// 构建请求体数据
	formData := url.Values{}
	formData.Set("username", a.email)
	formData.Set("password", a.password)
	body := strings.NewReader(formData.Encode())

	req, err := http.NewRequest("POST", urlStr, body)
	if err != nil {
		return "", fmt.Errorf("error creating request: %v", err)
	}
	req.Header.Set("User-Agent", a.userAgent)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	a.session.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	resp, err := a.session.Do(req)
	if err != nil {
		return "", fmt.Errorf("error getting access token: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		var response struct {
			AccessToken string `json:"accessToken"`
			ExpiresIn   int    `json:"expires"`
		}
		err := json.NewDecoder(resp.Body).Decode(&response)
		if err != nil {
			return "", fmt.Errorf("get access token failed.: %v", err)
		}

		if response.AccessToken == "" {
			return "", errors.New("get access token failed")
		}

		a.accessToken = response.AccessToken
		expiresAt := time.Now().UTC().Add(time.Second * time.Duration(response.ExpiresIn)).Add(-5 * time.Minute)
		a.expires = expiresAt
		return a.accessToken, nil
	}

	return "", errors.New("error get access token")
}
