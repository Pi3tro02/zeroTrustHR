#!/bin/bash

# 1. Avvia ulogd2 in background
ulogd -d -c /etc/ulogd.conf

# 2. Applica le regole di nftables
nft -f /etc/nftables.conf

# 3. Aspetta un secondo per far creare il file di log a ulogd2
sleep 1
touch /var/log/ulogd/nftables.json

# 4. Invece di bloccarci con 'tail -f /dev/null', leggiamo il file JSON.
# In questo modo, ogni riga JSON scritta da ulogd2 finirà nello Standard Output del container!
tail -f /var/log/ulogd/nftables.json