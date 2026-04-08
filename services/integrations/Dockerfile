FROM rust:1.90-slim AS builder
WORKDIR /app
COPY . .
RUN cargo build --release -p integrations

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /app/target/release/integrations /usr/local/bin/integrations
EXPOSE 8089
CMD ["/usr/local/bin/integrations"]
