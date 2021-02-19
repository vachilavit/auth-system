package main

import (
	"context"
	"fmt"
	"log"
	"time"

	authpb "github.com/vachilavit/auth-system/proto/auth"

	"google.golang.org/grpc"
	_ "google.golang.org/grpc/health"
	"google.golang.org/grpc/resolver"
	"google.golang.org/grpc/resolver/manual"
)

var serviceConfig = `{
	"loadBalancingPolicy": "round_robin",
	"healthCheckConfig": {
		"serviceName": ""
	}
}`

func callLogin(c authpb.AuthClient) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	r, err := c.Login(ctx, &authpb.LoginRequest{Username: "admin", Password: "admin"})
	if err != nil {
		fmt.Println("Login: _, ", err)
	} else {
		fmt.Println("Login: ", r.GetAccessToken())
	}
}

func main() {
	r := manual.NewBuilderWithScheme("whatever")
	r.InitialState(resolver.State{
		Addresses: []resolver.Address{
			{Addr: "localhost:50051"},
		},
	})

	address := fmt.Sprintf("%s:///unused", r.Scheme())

	options := []grpc.DialOption{
		grpc.WithInsecure(),
		grpc.WithBlock(),
		grpc.WithResolvers(r),
		grpc.WithDefaultServiceConfig(serviceConfig),
	}
	conn, err := grpc.Dial(address, options...)
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()

	c := authpb.NewAuthClient(conn)
	callLogin(c)
}
