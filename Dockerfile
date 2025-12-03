FROM golang:1.25-alpine AS builder

# Set the working directory inside the container
WORKDIR /app

# Copy go mod and sum files
COPY go.mod go.sum ./

# Download all dependencies
RUN go mod download

# Copy the source code into the container
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -o /olm

# Start a new stage from scratch
FROM alpine:3.23 AS runner

RUN apk --no-cache add ca-certificates

# Copy the pre-built binary file from the previous stage and the entrypoint script
COPY --from=builder /olm /usr/local/bin/
COPY entrypoint.sh /

RUN chmod +x /entrypoint.sh

# Copy the entrypoint script
ENTRYPOINT ["/entrypoint.sh"]

# Command to run the executable
CMD ["olm"]