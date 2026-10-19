FROM python:3.12-alpine

RUN apk add --no-cache iproute2 iputils

RUN pip install --no-cache-dir flask

WORKDIR /app

COPY camera/app.py .
COPY camera/templates ./templates
COPY config/devices_config.py .
COPY common/mfa.py .
COPY common/audit.py .
COPY common/templates ./templates

CMD ["python", "app.py"]
