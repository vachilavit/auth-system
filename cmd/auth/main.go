package main

import (
	"log"
	"net"

	"github.com/vachilavit/auth-system/internal/auth/repo"
	pb "github.com/vachilavit/auth-system/proto/auth"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	"google.golang.org/grpc"
)

const (
	port = ":50051"
)

func main() {
	lis, err := net.Listen("tcp", port)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	s := grpc.NewServer()
	healthcheck := health.NewServer()

	healthpb.RegisterHealthServer(s, healthcheck)
	pb.RegisterAuthServer(s, &repo.Server{})

	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
