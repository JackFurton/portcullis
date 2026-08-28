# One image, four binaries: the authorization service, and the three pieces the
# demo needs so it runs with nothing pulled from a registry but Envoy itself.
FROM golang:1.26 AS builder
ARG TARGETOS
ARG TARGETARCH
# Stamped into the binary so a running pod can say what it is.
ARG VERSION=dev

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build -trimpath -ldflags "-s -w -X github.com/JackFurton/portcullis/internal/version.Version=${VERSION}" -o /out/portcullis ./cmd/portcullis
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build -trimpath -ldflags "-s -w" -o /out/demoidp ./cmd/demoidp
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build -trimpath -ldflags "-s -w" -o /out/echo ./cmd/echo

FROM gcr.io/distroless/static:nonroot
COPY --from=builder /out/portcullis /portcullis
COPY --from=builder /out/demoidp /demoidp
COPY --from=builder /out/echo /echo
USER 65532:65532

EXPOSE 9191 9192
ENTRYPOINT ["/portcullis"]
