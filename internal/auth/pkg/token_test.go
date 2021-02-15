package token

import (
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go/v4"
	"github.com/vachilavit/auth-system/internal/auth/testdata"
	testhelper "github.com/vachilavit/auth-system/pkg"
)

func TestWithAccessTokenExpAt(t *testing.T) {
	arg := time.Now().Add(time.Minute)
	want := jwt.At(arg)

	tk := New(WithAccessTokenExpAt(arg))

	if !tk.AccessTokenClaims.ExpiresAt.Time.Equal(want.Time) {
		t.Errorf("WithAccessTokenExpAt(%v) got = %v, want = %v", arg, tk.AccessTokenClaims.ExpiresAt, want)
	}
}

func TestWithRefreshTokenExpAt(t *testing.T) {
	arg := time.Now().Add(time.Hour)
	want := jwt.At(arg)

	tk := New(WithRefreshTokenExpAt(arg))

	if !tk.RefreshTokenClaims.ExpiresAt.Time.Equal(want.Time) {
		t.Errorf("WithRefreshTokenExpAt(%v) got = %v, want = %v", arg, tk.AccessTokenClaims.ExpiresAt, want)
	}
}

func TestWithAccessTokenSecretKey(t *testing.T) {
	arg := "secretkey"
	want := arg

	tk := New(WithAccessTokenSecretKey(arg))

	if tk.AccessTokenSecretKey != want {
		t.Errorf("WithAccessTokenSecretKey(%v) got = %v, want = %v", arg, tk.AccessTokenSecretKey, want)
	}
}

func TestWithRefreshTokenSecretKey(t *testing.T) {
	arg := "secretkey2"
	want := arg

	tk := New(WithRefreshTokenSecretKey(arg))

	if tk.RefreshTokenSecretKey != want {
		t.Errorf("WithRefreshTokenSecretKey(%v) got = %v, want = %v", arg, tk.RefreshTokenSecretKey, want)
	}
}

func TestComposeClaimsWithUser(t *testing.T) {
	arg := testdata.UserData()
	wantUsername := arg.Username
	wantUserID := arg.ID
	wantSaltForRefreshTokenSecretKey := arg.HashedPassword

	tk := New(ComposeClaimsWithUser(arg))

	switch {
	case tk.AccessTokenClaims.Username != wantUsername:
		t.Errorf("ComposeClaimsWithUser(%v) got = %v, want = %v", arg, tk.AccessTokenClaims.Username, wantUsername)
	case tk.RefreshTokenClaims.UserID != wantUserID:
		t.Errorf("ComposeClaimsWithUser(%v) got = %v, want = %v", arg, tk.RefreshTokenClaims.ID, wantUserID)
	case tk.SaltForRefreshTokenSecretKey != wantSaltForRefreshTokenSecretKey:
		t.Errorf("ComposeClaimsWithUser(%v) got = %v, want = %v", arg, tk.RefreshTokenSecretKey, wantSaltForRefreshTokenSecretKey)
	}
}

func TestTokenGenerate(t *testing.T) {
	user := testdata.UserData()
	tk := New(ComposeClaimsWithUser(user), WithAccessTokenExpAt(time.Unix(0, 0)), WithRefreshTokenExpAt(time.Unix(0, 0)))

	// {"username": "admin", "exp": 0}
	wantAccessTokenString := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiZXhwIjowfQ.5LM5CD5guK4UZe4KwKYjeih3Yh1m_DPlTTzfF8D9r0"
	// {"userID": "e3e832db-b725-4fd5-94be-0ca4bc112e7d", "exp": 0}
	wantRefreshTokenString := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySUQiOiJlM2U4MzJkYi1iNzI1LTRmZDUtOTRiZS0wY2E0YmMxMTJlN2QiLCJleHAiOjB9.RcKHvdZnfAKQlvR2PZ8_BcgU1Fn7pi2divr-Jl2wAdk"

	accessTokenString, refreshTokenString, err := tk.Generate()
	if err != nil {
		t.Errorf("TokenGenerate() error = %v gotAccessTokenString = %v, gotAccessRefreshTokenString = %v, wantAccessTokenString = %v, wantRefreshTokenString = %v", err, accessTokenString, refreshTokenString, wantAccessTokenString, wantRefreshTokenString)
	}

	switch {
	case accessTokenString != wantAccessTokenString:
		testhelper.Assert(t, false, "dsadfe")
		// t.Errorf("TokenGenerate() gotAccessTokenString = %v, wantAccessTokenString = %v", accessTokenString, wantAccessTokenString)
	case refreshTokenString != wantRefreshTokenString:
		t.Errorf("TokenGenerate() gotAccessRefreshTokenString = %v, wantRefreshTokenString = %v", refreshTokenString, wantRefreshTokenString)
	}
}
