# Usa un'immagine Debian leggera
FROM debian:stable-slim

# 1. Installa nftables, gli strumenti di rete e, FONDAMENTALE, ulogd2 con il plugin JSON
RUN apt-get update && \
    apt-get install -y nftables iproute2 ulogd2 ulogd2-json procps && \
    apt-get clean

# 2. Copia le configurazioni
COPY nftables.conf /etc/nftables.conf
COPY ulogd.conf /etc/ulogd.conf

# 3. Crea la directory per i file di log di ulogd2
RUN mkdir -p /var/log/ulogd 

# 4. Copia lo script di avvio personalizzato e rendilo eseguibile
COPY start.sh /start.sh
RUN chmod +x /start.sh

# 5. Usa lo script come entrypoint
CMD ["/start.sh"]