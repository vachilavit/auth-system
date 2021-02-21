package service

import (
	"errors"

	"github.com/vachilavit/auth-system/internal/auth/model"
	token "github.com/vachilavit/auth-system/internal/auth/pkg"
	pb "github.com/vachilavit/auth-system/proto/auth"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrInvalidUsernamOrPassword = errors.New("Invalid username or password")
)

func Login(in *pb.LoginRequest) (*pb.LoginReply, error) {
	// mock
	user := model.User{
		ID:             "e3e832db-b725-4fd5-94be-0ca4bc112e7d",
		Username:       "admin",
		HashedPassword: "$2a$12$UXkOa4CGS0nHH2FEXFYvauyjlYLSEsBJp2ZHnkzV64rJYnEkWNkAG",
	}

	tk := token.New(token.ComposeClaimsWithUser(user))

	errCompare := bcrypt.CompareHashAndPassword([]byte(user.HashedPassword), []byte(in.Password))
	if errCompare != nil {
		return nil, errCompare
	}
	if user.Username == in.Username && errCompare == nil {
		accessTokenString, refreshTokenString, err := tk.Generate()
		if err != nil {
			return nil, err
		}
		return &pb.LoginReply{AccessToken: accessTokenString, RefreshToken: refreshTokenString}, nil
	}

	return nil, ErrInvalidUsernamOrPassword
}
