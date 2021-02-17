auth-dev:
	cd ./cmd/auth && go run main.go

client-dev: 
	cd ./cmd/client && go run main.go

proto: ./proto/*
	$(foreach var,$^,protoc --go_out=plugins=grpc:. $(var)/*.proto && ) echo.

.PHONY: \
	auth-dev \
	client-dev \
	proto