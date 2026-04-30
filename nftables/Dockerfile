FROM debian:stable-slim

RUN apt-get update && \
    apt-get install -y nftables iproute2 && \
    apt-get clean

COPY nftables.conf /etc/nftables.conf

CMD sh -c "nft -f /etc/nftables.conf && tail -f /dev/null"