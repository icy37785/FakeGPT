package pandora

import (
	"fmt"
	"github.com/golang-jwt/jwt"
	"strings"
)

// CheckAccessToken 检查token并且返回payload
func CheckAccessToken(accessToken string) (jwt.MapClaims, error) {
	// 从Pandora的源码里面拿到的openai的公钥
	publicKey := `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA27rOErDOPvPc3mOADYtQ
BeenQm5NS5VHVaoO/Zmgsf1M0Wa/2WgLm9jX65Ru/K8Az2f4MOdpBxxLL686ZS+K
7eJC/oOnrxCRzFYBqQbYo+JMeqNkrCn34yed4XkX4ttoHi7MwCEpVfb05Qf/ZAmN
I1XjecFYTyZQFrd9LjkX6lr05zY6aM/+MCBNeBWp35pLLKhiq9AieB1wbDPcGnqx
lXuU/bLgIyqUltqLkr9JHsf/2T4VrXXNyNeQyBq5wjYlRkpBQDDDNOcdGpx1buRr
Z2hFyYuXDRrMcR6BQGC0ur9hI5obRYlchDFhlb0ElsJ2bshDDGRk5k3doHqbhj2I
gQIDAQAB
-----END PUBLIC KEY-----`

	// 解析token
	token, err := jwt.Parse(accessToken, func(token *jwt.Token) (interface{}, error) {
		publicKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(publicKey))
		if nil != err {
			return nil, fmt.Errorf("failed to parse public key: %v", err)
		}
		return publicKey, nil
	})

	if nil != err {
		return nil, fmt.Errorf("failed to parse token: %v", err)
	}

	// 验证 JWT 的有效性
	if !token.Valid {
		return nil, fmt.Errorf("invalid JWT")
	}

	// 获取 payload
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("failed to get JWT claims")
	}
	if _, ok := claims["scope"]; !ok {
		return nil, fmt.Errorf("miss scope")
	}
	scope := claims["scope"]
	if !strings.Contains(scope.(string), "model.read") || !strings.Contains(scope.(string), "model.request") {
		return nil, fmt.Errorf("invalid scope")
	}
	_, ok1 := claims["https://api.openai.com/auth"]
	_, ok2 := claims["https://api.openai.com/profile"]
	if !ok1 || !ok2 {
		return nil, fmt.Errorf("belonging to an unregistered user")
	}

	return claims, nil
}

// CheckUserInfo 解析传入的access token
func CheckUserInfo(accessToken string) (string, string, string, jwt.MapClaims, error) {
	payload, err := CheckAccessToken(accessToken)
	if nil != err {
		return "", "", "", nil, fmt.Errorf("failed to check access token: %v", err)
	}
	// 使用类型断言访问声明中的属性
	var email, userID string
	if profile, ok := payload["https://api.openai.com/profile"].(map[string]interface{}); ok {
		if emailVal, ok := profile["email"].(string); !ok {
			return "", "", "", nil, fmt.Errorf("failed to get email")
		} else {
			email = emailVal
		}
	}

	if auth, ok := payload["https://api.openai.com/auth"].(map[string]interface{}); ok {
		if userIDVal, ok := auth["user_id"].(string); !ok {
			return "", "", "", nil, fmt.Errorf("failed to get user_id")
		} else {
			userID = userIDVal
		}
	}
	return userID, email, accessToken, payload, nil
}
