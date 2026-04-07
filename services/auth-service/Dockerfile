FROM rust:1.78-slim AS builder
WORKDIR /app
COPY . .
RUN cargo build --release -p auth-service

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /app/target/release/auth-service /usr/local/bin/auth-service
EXPOSE 8081
CMD ["/usr/local/bin/auth-service"]
