#!/bin/bash

mkdir -p build
go build -o build/main *.go || exit 1

sudo ./build/main ns-reassmble "$@"
