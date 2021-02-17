package token

import (
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vachilavit/auth-system/internal/auth/testdata"
)

func TestWithAccessTokenExpAt(t *testing.T) {
	arg := time.Now().Add(time.Minute)
	want := jwt.At(arg)
	tk := New(WithAccessTokenExpAt(arg))
	assert.Equal(t, want.Time, tk.AccessTokenClaims.ExpiresAt.Time, "AccessTokenClaims.ExpiresAt.Time should be equal")
}

func TestWithRefreshTokenExpAt(t *testing.T) {
	arg := time.Now().Add(time.Hour)
	want := jwt.At(arg)
	tk := New(WithRefreshTokenExpAt(arg))
	assert.Equal(t, want.Time, tk.RefreshTokenClaims.ExpiresAt.Time, "RefreshTokenClaims.ExpiresAt.Time should be equal")
}

func TestWithAccessTokenSecretKey(t *testing.T) {
	arg := "secretkey"
	want := arg
	tk := New(WithAccessTokenSecretKey(arg))
	assert.Equal(t, want, tk.AccessTokenSecretKey, "AccessTokenSecretKey should be equal")
}

func TestWithRefreshTokenSecretKey(t *testing.T) {
	arg := "secretkey2"
	want := arg
	tk := New(WithRefreshTokenSecretKey(arg))
	assert.Equal(t, want, tk.RefreshTokenSecretKey, "RefreshTokenSecretKey should be equal")
}

func TestComposeClaimsWithUser(t *testing.T) {
	arg := testdata.UserData()
	wantUsername := arg.Username
	wantUserID := arg.ID
	wantSaltForRefreshTokenSecretKey := arg.HashedPassword
	tk := New(ComposeClaimsWithUser(arg))
	assert.Equal(t, wantUsername, tk.AccessTokenClaims.Username, "AccessTokenClaims.Username should be equal")
	assert.Equal(t, wantUserID, tk.RefreshTokenClaims.UserID, "RefreshTokenClaims.UserID should be equal")
	assert.Equal(t, wantSaltForRefreshTokenSecretKey, tk.SaltForRefreshTokenSecretKey, "SaltForRefreshTokenSecretKey should be equal")
}

func TestTokenGenerate(t *testing.T) {
	user := testdata.UserData()
	tk := New(ComposeClaimsWithUser(user), WithAccessTokenExpAt(time.Unix(0, 0)), WithRefreshTokenExpAt(time.Unix(0, 0)))

	// {"username": "admin", "exp": 0}
	wantAccessTokenString := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiZXhwIjowfQ.5LM5CD5guK4UZe4KwKYjeih3Yh1m_DPlTTzfF8D9r0M"
	// {"userID": "e3e832db-b725-4fd5-94be-0ca4bc112e7d", "exp": 0}
	wantRefreshTokenString := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySUQiOiJlM2U4MzJkYi1iNzI1LTRmZDUtOTRiZS0wY2E0YmMxMTJlN2QiLCJleHAiOjB9.RcKHvdZnfAKQlvR2PZ8_BcgU1Fn7pi2divr-Jl2wAdk"

	accessTokenString, refreshTokenString, err := tk.Generate()
	require.Nil(t, err, "Generate() should be nil")

	assert.Equal(t, wantAccessTokenString, accessTokenString, "accessTokenString should be equal")
	assert.Equal(t, wantRefreshTokenString, refreshTokenString, "refreshTokenString should be equal")
}
