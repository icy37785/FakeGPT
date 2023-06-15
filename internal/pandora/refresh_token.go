package pandora

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

type RefreshData struct {
	RedirectUri  string `json:"redirect_uri"`
	GrantType    string `json:"grant_type"`
	ClientId     string `json:"client_id"`
	RefreshToken string `json:"refresh_token"`
}

// refreshPostToken 向网页post数据
func refreshPostToken(url string, data RefreshData, userAgent string) (*http.Response, error) {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("编码数据失败: %v", err)
	}
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("创建请求失败: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent)
	client := &http.Client{}
	rep, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("发送请求失败: %v", err)
	}

	return rep, nil
}

// GetTokenByRefreshToken 依据refresh_token获取access_token
func GetTokenByRefreshToken(RefreshToken string) (string, error) {
	data := RefreshData{
		RedirectUri: "com.openai.chat://auth0.openai.com/ios/com.openai.chat/callback",
		GrantType:   "refresh_token",
		ClientId:    "pdlLIX2Y72MIl2rhLhTE9VV9bN905kBh",
	}
	data.RefreshToken = RefreshToken

	url := "https://auth0.openai.com/oauth/token"
	resp, err := refreshPostToken(url, data, userAgent)
	if err != nil {
		return "", err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
		}
	}(resp.Body)

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

		//expiresAt := time.Now().UTC().Add(time.Second * time.Duration(response.ExpiresIn)).Add(-5 * time.Minute)
		return response.AccessToken, nil
	}
	return "", fmt.Errorf("error getting access token: %s", resp.Status)
}
