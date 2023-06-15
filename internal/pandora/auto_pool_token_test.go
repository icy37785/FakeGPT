package pandora

import (
	"fmt"
	"testing"
)

func TestCreateShareTokenByEmail(t *testing.T) {
	email := "xxx@example.com"
	password := "xxxx"

	shareToken, err := CreateShareTokenByEmail(email, password, "")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	fmt.Println("share_token:", shareToken)
}

func TestCreateShareTokenByAccessToken(t *testing.T) {
	accessToken := "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
	shareToken, err := CreateShareTokenByAccessToken(accessToken, "")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	fmt.Println("share_token:", shareToken)
}

func TestCreatePoolToken(t *testing.T) {
	shareTokens := []string{
		"xxxxxxxx",
	}
	poolToken, err := CreatePoolToken(shareTokens)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	fmt.Println("pool_token:", poolToken)
}
