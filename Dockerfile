FROM rust:1.66 AS builder

COPY . .

RUN cargo build --release

FROM debian:bullseye-slim

RUN groupadd -r portlurker && useradd -r -g portlurker portlurker

WORKDIR /opt/portlurker

COPY --from=builder ./target/release/portlurker /opt/portlurker/portlurker
COPY ./config.yml-default /opt/portlurker/config.yml

RUN chown -R portlurker:portlurker /opt/portlurker
USER portlurker

CMD ["/opt/portlurker/portlurker"]
