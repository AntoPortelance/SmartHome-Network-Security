FROM python:3.12-alpine

RUN apk add --no-cache \
    iproute2 \
    iputils

RUN pip install --no-cache-dir flask

WORKDIR /app

COPY smartTV/app.py .
COPY smartTV/templates ./templates
COPY common/audit.py .
COPY config/devices_config.py .

CMD ["python", "app.py"]
