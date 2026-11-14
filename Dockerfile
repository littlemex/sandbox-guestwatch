# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM public.ecr.aws/docker/library/golang:1.26 AS build
ARG TARGETOS TARGETARCH VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags "-s -w -X main.version=$VERSION" -o /guestwatch ./cmd/guestwatch

FROM scratch
COPY --from=build /guestwatch /guestwatch
ENTRYPOINT ["/guestwatch"]
