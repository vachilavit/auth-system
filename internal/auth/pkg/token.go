package token

import (
	"time"

	"github.com/dgrijalva/jwt-go"

	"github.com/vachilavit/auth-system/internal/auth/model"
)

type AccessTokenClaims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

type RefreshTokenClaims struct {
	UserID string `json:"userID"`
	jwt.StandardClaims
}

type AccessAndRefreshToken interface {
	Generate() (accessTokenString, refreshTokenString string, err error)
}

type Token struct {
	AccessTokenClaims            AccessTokenClaims
	RefreshTokenClaims           RefreshTokenClaims
	AccessTokenSecretKey         string
	RefreshTokenSecretKey        string
	SaltForRefreshTokenSecretKey string
}

type Option func(*Token)

const (
	accessTokenSecretKey  = "5fe8a32fcfdbfb27b62d91a60606c966e840a703de55fcc95ea5c2a5744d12ce"
	refreshTokenSecretKey = "c919a17442389ee22bd51c0260c2f7cc780d37a2b45501e6c1101d91a6c158ec"
)

func WithAccessTokenExpAt(expAt time.Time) Option {
	return func(tk *Token) {
		tk.AccessTokenClaims.ExpiresAt = expAt.Unix()
	}
}

func WithRefreshTokenExpAt(expAt time.Time) Option {
	return func(tk *Token) {
		tk.RefreshTokenClaims.ExpiresAt = expAt.Unix()
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
			StandardClaims: jwt.StandardClaims{ExpiresAt: (time.Now().Add(time.Minute * 5)).Unix()},
		},
		RefreshTokenClaims: RefreshTokenClaims{
			StandardClaims: jwt.StandardClaims{ExpiresAt: (time.Now().Add(time.Hour * 24 * 7)).Unix()},
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

func (tk *Token) Generate() (accessTokenString, refreshTokenString string, err error) {
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, tk.AccessTokenClaims)
	if accessTokenString, err = accessToken.SignedString([]byte(tk.AccessTokenSecretKey)); err != nil {
		return
	}
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, tk.RefreshTokenClaims)
	if refreshTokenString, err = refreshToken.SignedString([]byte(tk.RefreshTokenSecretKey + tk.SaltForRefreshTokenSecretKey)); err != nil {
		return
	}

	return
}
