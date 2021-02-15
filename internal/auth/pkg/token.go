package token

import (
	"time"

	"github.com/dgrijalva/jwt-go/v4"

	"github.com/vachilavit/auth-system/internal/auth/model"
)

const (
	accessTokenSecretKey  = "5fe8a32fcfdbfb27b62d91a60606c966e840a703de55fcc95ea5c2a5744d12ce"
	refreshTokenSecretKey = "c919a17442389ee22bd51c0260c2f7cc780d37a2b45501e6c1101d91a6c158ec"
)

type AccessTokenClaims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

type RefreshTokenClaims struct {
	UserID string `json:"userID"`
	jwt.StandardClaims
}

type Token struct {
	AccessTokenClaims            AccessTokenClaims
	RefreshTokenClaims           RefreshTokenClaims
	AccessTokenSecretKey         string
	RefreshTokenSecretKey        string
	SaltForRefreshTokenSecretKey string
}

type Option func(*Token)

func WithAccessTokenExpAt(expAt time.Time) Option {
	return func(tk *Token) {
		tk.AccessTokenClaims.ExpiresAt = jwt.At(expAt)
	}
}

func WithRefreshTokenExpAt(expAt time.Time) Option {
	return func(tk *Token) {
		tk.RefreshTokenClaims.ExpiresAt = jwt.At(expAt)
	}
}

func WithAccessTokenSecretKey(secrestKey string) Option {
	return func(tk *Token) {
		tk.AccessTokenSecretKey = secrestKey
	}
}

func WithRefreshTokenSecretKey(secrestKey string) Option {
	return func(tk *Token) {
		tk.RefreshTokenSecretKey = secrestKey
	}
}

func ComposeClaimsWithUser(user model.User) Option {
	return func(tk *Token) {
		tk.AccessTokenClaims.Username = user.Username
		tk.RefreshTokenClaims.UserID = user.ID
		tk.SaltForRefreshTokenSecretKey = user.HashedPassword
	}
}

func New(opts ...Option) *Token {
	// default
	tk := &Token{
		AccessTokenClaims: AccessTokenClaims{
			StandardClaims: jwt.StandardClaims{ExpiresAt: jwt.At(time.Now().Add(time.Minute * 5))},
		},
		RefreshTokenClaims: RefreshTokenClaims{
			StandardClaims: jwt.StandardClaims{ExpiresAt: jwt.At(time.Now().Add(time.Hour * 24 * 7))},
		},
		AccessTokenSecretKey:  accessTokenSecretKey,
		RefreshTokenSecretKey: refreshTokenSecretKey,
	}

	// Loop through each option
	for _, opt := range opts {
		// Call the option giving the instantiated
		opt(tk)
	}

	return tk
}

func (t *Token) Generate() (accessTokenString, refreshTokenString string, err error) {
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, t.AccessTokenClaims)
	if accessTokenString, err = accessToken.SignedString([]byte(t.AccessTokenSecretKey)); err != nil {
		return
	}
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, t.RefreshTokenClaims)
	if refreshTokenString, err = refreshToken.SignedString([]byte(t.RefreshTokenSecretKey + t.SaltForRefreshTokenSecretKey)); err != nil {
		return
	}

	return
}
