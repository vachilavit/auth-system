package main

import (
	"context"
	"log"
	"time"

	authpb "github.com/vachilavit/auth-system/proto/auth"

	"google.golang.org/grpc"
)

const (
	address = "localhost:50051"
)

func main() {
	conn, err := grpc.Dial(address, grpc.WithInsecure(), grpc.WithBlock())
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()
	c := authpb.NewAuthClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	r, err := c.Login(ctx, &authpb.LoginRequest{Username: "admin", Password: "admin"})
	if err != nil {
		log.Fatalf("could not greet: %v", err)
	}
	log.Printf("AccessToken: %s", r.GetAccessToken())
}
