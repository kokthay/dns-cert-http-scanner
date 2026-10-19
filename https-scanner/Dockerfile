# Override GO_IMAGE to pin an approved toolchain image/digest.
ARG GO_IMAGE=golang:1-alpine
FROM ${GO_IMAGE} AS build
WORKDIR /src
ENV CGO_ENABLED=0 GOTOOLCHAIN=local
COPY go.mod ./
COPY *.go ./
RUN go test ./... && go build -buildvcs=false -trimpath -ldflags="-s -w" -o /https-scanner .

FROM scratch
COPY --from=build /https-scanner /https-scanner
WORKDIR /work
ENTRYPOINT ["/https-scanner"]
