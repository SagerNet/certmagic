#!/usr/bin/env bash

PROJECTS=$(dirname "$0")/../..

go get -x github.com/sagernet/sing-dns@$(git -C $PROJECTS/sing-dns rev-parse HEAD)
go mod tidy
