# Build stage
FROM golang:1.24.5-alpine AS builder

WORKDIR /build

# Install build dependencies
RUN apk add --no-cache gcc musl-dev

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=1 GOOS=linux go build -o main .

# Final stage
FROM alpine:3.19

WORKDIR /app

# Install runtime dependencies
RUN apk add --no-cache ca-certificates

# Create necessary directories
RUN mkdir -p /app/config

# Copy binary from builder
COPY --from=builder /build/main .

# Copy config files
COPY config/ /app/config/

# Run the application
CMD ["./main"]