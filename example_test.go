package auth_test

import (
	"fmt"

	auth "github.com/waywake/auth-sdk-go"
)

func ExampleClient_AuthorizeURL() {
	client, err := auth.NewClient(auth.Config{BaseURL: "https://auth.example.com", ClientID: 42})
	if err != nil {
		panic(err)
	}
	challenge, err := auth.CodeChallenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
	if err != nil {
		panic(err)
	}
	loginURL, err := client.AuthorizeURL(auth.AuthorizeParams{
		RedirectURI: "https://app.example.com/callback", Scopes: []auth.Scope{auth.ScopeProfileRead},
		State: "0123456789abcdefghijklmnopqrstuvwxyzABCDEFG", CodeChallenge: challenge,
	})
	if err != nil {
		panic(err)
	}
	fmt.Println(loginURL)
	// Output: https://auth.example.com/openapi/v1/oauth/authorize?client_id=42&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback&response_type=code&scope=profile%3Aread&state=0123456789abcdefghijklmnopqrstuvwxyzABCDEFG
}

func ExampleCodeChallenge() {
	challenge, err := auth.CodeChallenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
	if err != nil {
		panic(err)
	}
	fmt.Println(challenge)
	// Output: E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
}
