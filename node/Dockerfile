# Build stage
FROM golang:1.25-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o node .
RUN mkdir /data && chown 65532:65532 /data

# Final stage
FROM gcr.io/distroless/static:nonroot
COPY --from=builder --chown=65532:65532 /data /data
COPY --from=builder /app/node /node
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
USER nonroot:nonroot
EXPOSE 8080 443
ENTRYPOINT ["/node"]
