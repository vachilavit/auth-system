package repo

import (
	"context"

	"github.com/vachilavit/auth-system/internal/auth/service"
	pb "github.com/vachilavit/auth-system/proto/auth"
)

type Server struct {
	pb.UnimplementedAuthServer
}

func (s *Server) Login(ctx context.Context, in *pb.LoginRequest) (*pb.LoginReply, error) {
	return service.Login(in)
}

func (s *Server) GenerateToken(ctx context.Context, in *pb.GenerateTokenRequest) (*pb.GenerateTokenReply, error) {
	return service.GenerateToken(in)
}
