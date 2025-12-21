FROM rust:1.92-trixie AS builder

WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY dictionary.toml ./
COPY src ./src
RUN cargo build --release

FROM debian:trixie-slim

RUN useradd -r -u 10001 -g root -d /nonexistent -s /usr/sbin/nologin nanoradius

COPY --from=builder /app/target/release/nanoRadius /usr/local/bin/nanoRadius
COPY docker/nanoradius.toml /etc/nanoradius/nanoradius.toml
COPY docker/users.toml /etc/nanoradius/users.toml
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh

RUN chmod +x /usr/local/bin/entrypoint.sh \
  && mkdir -p /etc/nanoradius /var/log/nanoradius \
  && touch /var/log/nanoradius/nanoradius.log \
  && chown -R nanoradius:root /etc/nanoradius /var/log/nanoradius

EXPOSE 1812/udp 1813/udp
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["/usr/local/bin/nanoRadius","-c","/etc/nanoradius/nanoradius.toml"]
