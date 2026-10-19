FROM python:3.12-alpine

RUN apk add --no-cache \
    nftables \
    iproute2 \
    iputils \
    ulogd

RUN pip install --no-cache-dir flask

WORKDIR /app
COPY app.py supervisor.py ./
COPY templates ./templates

COPY firewall.nft /etc/firewall.nft
COPY ulogd.conf /etc/ulogd.conf
COPY start.sh /start.sh

RUN chmod +x /start.sh

CMD ["/start.sh"]
