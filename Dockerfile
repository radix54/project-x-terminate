# syntax=docker/dockerfile:1

FROM golang:1.27.3 AS builder
WORKDIR /app
# Cache dependencies to speed up builds
COPY go.* ./

#RUN go mod download
# Copy the Makefiles
COPY Makefile ./

# Copy the source code
COPY mldsa44/ mldsa44/
COPY internal/ internal/
COPY cmd/*.go cmd/
# KAT
COPY kat/ kat/

# Build the application
RUN make build

ENTRYPOINT [ "make", "run", ";", "make", "test" ]
