FROM golang:1.22 AS builder

LABEL org.opencontainers.image.source=https://github.com/shipperizer/iam-ext-authz

ARG SKAFFOLD_GO_GCFLAGS
ARG TARGETOS
ARG TARGETARCH

ENV GOOS=$TARGETOS
ENV GOARCH=$TARGETARCH
ENV GO111MODULE=on
ENV CGO_ENABLED=0
ENV GO_BIN=/go/bin/app

WORKDIR /var/app

COPY . .

RUN make build

FROM gcr.io/distroless/static:nonroot

LABEL org.opencontainers.image.source=https://github.com/shipperizer/iam-ext-authz

COPY --from=builder /go/bin/app /app

CMD ["/app", "serve"]