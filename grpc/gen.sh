#!/usr/bin/env bash

# generate the gRPC code
protoc --go_out=paths=source_relative:. --go-grpc_out=paths=source_relative:. \
    auth.proto