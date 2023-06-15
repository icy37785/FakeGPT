package pandora

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// CreateShareTokenByEmail 依据email生成share_token
func CreateShareTokenByEmail(email, password, uniqueName string) (string, error) {
	auth := NewAuth0(email, password, "", false, "")
	accessToken, err := auth.Auth(true)
	if err != nil {
		return "", err
	}

	return CreateShareTokenByAccessToken(accessToken, uniqueName)
}

// CreateShareTokenByAccessToken 依据access_token生成share_token
func CreateShareTokenByAccessToken(accessToken, uniqueName string) (string, error) {
	urlStr := "https://ai.fakeopen.com/token/register"

	// 构建请求体数据
	formData := url.Values{}
	formData.Set("unique_name", uniqueName)
	formData.Set("access_token", accessToken)
	formData.Set("expires_in", "0")
	body := strings.NewReader(formData.Encode())
	resp, err := http.Post(urlStr, "application/x-www-form-urlencoded", body)
	if err != nil {
		return "", fmt.Errorf("error getting share token: %v", err)
	}

	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {

		}
	}(resp.Body)

	if resp.StatusCode == http.StatusOK {
		var response struct {
			UniqueName        string `json:"unique_name"`
			ShareToken        string `json:"token_key"`
			SiteLimit         string `json:"site_limit"`
			ShowUserinfo      bool   `json:"show_userinfo"`
			ShowConversations bool   `json:"show_conversations"`
			ExpiresIn         int    `json:"expire_at"`
		}
		err := json.NewDecoder(resp.Body).Decode(&response)
		if err != nil {
			return "", fmt.Errorf("get share token failed.: %v", err)
		}

		if response.ShareToken == "" {
			return "", errors.New("get share token failed")
		}

		return response.ShareToken, nil
	}
	return "", fmt.Errorf("share token failed: %s", resp.Body)
}

// CreatePoolToken 依据share_token生成pool_token
func CreatePoolToken(shareTokens []string) (string, error) {
	return UpdatePoolToken(shareTokens, "")
}

// UpdatePoolToken 更新pool_token
func UpdatePoolToken(shareTokens []string, poolToken string) (string, error) {
	urlStr := "https://ai.fakeopen.com/pool/update"

	// 构建请求体数据
	formData := url.Values{}
	formData.Set("share_tokens", strings.Join(shareTokens, "\n"))
	formData.Set("pool_token", poolToken)
	body := strings.NewReader(formData.Encode())
	resp, err := http.Post(urlStr, "application/x-www-form-urlencoded", body)
	if err != nil {
		return "", fmt.Errorf("error getting pool token: %v", err)
	}

	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {

		}
	}(resp.Body)

	if resp.StatusCode == http.StatusOK {
		var response struct {
			Count     int    `json:"count"`
			PoolToken string `json:"pool_token"`
		}
		err := json.NewDecoder(resp.Body).Decode(&response)
		if err != nil {
			return "", fmt.Errorf("get pool token failed.: %v", err)
		}

		if response.PoolToken == "" {
			return "", errors.New("get pool token failed")
		}

		return response.PoolToken, nil
	}
	return "", fmt.Errorf("generate pool token failed: %s", resp.Body)
}
