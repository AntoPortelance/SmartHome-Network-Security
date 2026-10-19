FROM python:3.12-alpine

RUN apk add --no-cache iproute2 iputils
RUN pip install --no-cache-dir flask

WORKDIR /app
COPY laptop/app.py .
COPY laptop/templates ./templates
COPY common/mfa.py .
COPY common/audit.py .
COPY common/templates ./templates
COPY config/devices_config.py .

CMD ["python", "app.py"]
