FROM debian:stable-slim

RUN apt-get update && \
    apt-get install -y nftables && \
    apt-get clean

COPY nftables.conf /etc/nftables.conf

CMD ["nft", "-f", "/etc/nftables.conf"]