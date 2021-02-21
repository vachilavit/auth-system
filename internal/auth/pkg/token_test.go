package token

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vachilavit/auth-system/internal/auth/testdata"
)

func TestWithAccessTokenExpAt(t *testing.T) {
	arg := time.Now().Add(time.Minute)
	want := arg
	tk := New(WithAccessTokenExpAt(arg))
	assert.Equal(t, want.Unix(), tk.AccessTokenClaims.ExpiresAt, "AccessTokenClaims.ExpiresAt.Time should be equal")
}

func TestWithRefreshTokenExpAt(t *testing.T) {
	arg := time.Now().Add(time.Hour)
	want := arg
	tk := New(WithRefreshTokenExpAt(arg))
	assert.Equal(t, want.Unix(), tk.RefreshTokenClaims.ExpiresAt, "RefreshTokenClaims.ExpiresAt.Time should be equal")
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
	tk := New()
	tk.AccessTokenClaims.Username = user.Username
	tk.RefreshTokenClaims.UserID = user.ID
	tk.SaltForRefreshTokenSecretKey = user.HashedPassword
	tk.AccessTokenClaims.ExpiresAt = 0
	tk.RefreshTokenClaims.ExpiresAt = 0

	// {"username": "admin"}
	wantAccessTokenString := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIn0.NlQn9Jtm8qUBqP4TitInCmwEz2JApz_QUzQbdCjm3CM"
	// {"userID": "e3e832db-b725-4fd5-94be-0ca4bc112e7d"}
	wantRefreshTokenString := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySUQiOiJlM2U4MzJkYi1iNzI1LTRmZDUtOTRiZS0wY2E0YmMxMTJlN2QifQ.UQDk1NXAVdD_94neSa3eHOt0yzM6Mukm2gysrPq6qIU"

	accessTokenString, refreshTokenString, err := tk.Generate()
	require.Nil(t, err, "Generate() should be nil")

	assert.Equal(t, wantAccessTokenString, accessTokenString, "accessTokenString should be equal")
	assert.Equal(t, wantRefreshTokenString, refreshTokenString, "refreshTokenString should be equal")
}
