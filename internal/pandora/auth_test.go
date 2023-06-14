package pandora

import (
	"fmt"
	"testing"
)

func TestAuthForToken(t *testing.T) {
	email := "xxx@example.com"
	password := "xxxx"

	auth := NewAuth0(email, password, "", false, "")
	accessToken, err := auth.Auth(true)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	fmt.Println("Access Token:", accessToken)
}

func TestAuthForTokenByProxy(t *testing.T) {
	email := "xxx@example.com"
	password := "xxxx"

	auth := NewAuth0(email, password, "", false, "")
	accessToken, err := auth.Auth(false)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	fmt.Println("Access Token:", accessToken)
}
