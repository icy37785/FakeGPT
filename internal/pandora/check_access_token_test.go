package pandora

import (
	"fmt"
	"testing"
)

func TestCheckAccessToken(t *testing.T) {
	accessToken := "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
	claims, err := CheckAccessToken(accessToken)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	fmt.Println("claims:", claims)
}

func TestCheckUserInfo(t *testing.T) {
	accessToken := "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
	userID, email, accessToken, payload, err := CheckUserInfo(accessToken)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	fmt.Println("userID:", userID)
	fmt.Println("email:", email)
	fmt.Println("Access Token:", accessToken)
	fmt.Println("payload:", payload)
}
