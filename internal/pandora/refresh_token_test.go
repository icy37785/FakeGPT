package pandora

import (
	"fmt"
	"testing"
)

func TestGetTokenByRefreshToken(t *testing.T) {
	refreshToken := "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

	accessToken, err := GetTokenByRefreshToken(refreshToken)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	fmt.Println("access token:", accessToken)
}
