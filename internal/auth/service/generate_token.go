package service

import (
	"github.com/vachilavit/auth-system/internal/auth/model"
	token "github.com/vachilavit/auth-system/internal/auth/pkg"
	pb "github.com/vachilavit/auth-system/proto/auth"
)

func GenerateToken(in *pb.GenerateTokenRequest) (*pb.GenerateTokenReply, error) {
	// mock
	user := model.User{
		ID:             "e3e832db-b725-4fd5-94be-0ca4bc112e7d",
		Username:       "admin",
		HashedPassword: "$2a$12$UXkOa4CGS0nHH2FEXFYvauyjlYLSEsBJp2ZHnkzV64rJYnEkWNkAG",
	}

	newToken := token.New(token.ComposeClaimsWithUser(user))
	accessTokenString, refreshTokenString, err := newToken.Generate()
	if err != nil {
		return nil, err
	}

	return &pb.GenerateTokenReply{AccessToken: accessTokenString, RefreshToken: refreshTokenString}, nil
}
