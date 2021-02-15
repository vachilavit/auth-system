package service

import (
	"encoding/hex"
	"errors"

	"crypto/sha256"

	"github.com/vachilavit/auth-system/internal/auth/model"
	token "github.com/vachilavit/auth-system/internal/auth/pkg"
	pb "github.com/vachilavit/auth-system/proto/auth"
)

func Login(in *pb.LoginRequest) (*pb.LoginReply, error) {
	// mock
	user := model.User{
		ID:             "e3e832db-b725-4fd5-94be-0ca4bc112e7d",
		Username:       "admin",
		HashedPassword: "ab0a8644e8ba7ffd7bdbde3773c66203117e41580b791be0ef7af5c96d794446",
		Salt:           "724409f8-92e1-4e1c-b0cc-cc463da985ee",
	}

	tk := token.New(token.ComposeClaimsWithUser(user))

	sum := sha256.Sum256([]byte(in.Password + user.Salt))
	hashedPasswordIncoming := hex.EncodeToString(sum[:])
	if user.Username == in.Username && user.HashedPassword == hashedPasswordIncoming {
		accessTokenString, refreshTokenString, err := tk.Generate()
		if err != nil {
			return nil, err
		}
		return &pb.LoginReply{AccessToken: accessTokenString, RefreshToken: refreshTokenString}, nil
	}

	return nil, errors.New("Invalid username or password")
}
