# Smart Home Security

This Docker lab simulates a laptop, a Smart TV, a camera, a guest phone, and a NAS on separate networks. An nftables router filters traffic between them and logs allowed and blocked packets. The camera, NAS, and laptop also use email MFA.

## Start the project

Start Docker, then run:

```sh
cd smart-home-security
docker compose up -d --build
docker compose ps -a
```

Run all commands below from `smart-home-security`. Real MFA emails require SMTP settings in `.env`; device credentials and recipient addresses are stored in `config/devices_config.py`. The network tests below do not require email configuration.

## Device addresses

- Camera: http://localhost:5001
- Smart TV: http://localhost:5002
- Guest phone: http://localhost:5003
- NAS: http://localhost:5004
- Laptop: http://localhost:5005
- Router: http://localhost:5006

## Test connections between devices

Use internal device IPs from inside the containers so traffic passes through the router.

Allowed connections — these should receive replies:

```sh
# Laptop -> Smart TV
docker compose exec laptop ping -c 3 -W 2 10.20.0.11

# Laptop -> Camera
docker compose exec laptop ping -c 3 -W 2 10.30.0.10

# Laptop -> NAS
docker compose exec laptop ping -c 3 -W 2 10.50.0.10

# Camera -> NAS
docker compose exec camera ping -c 3 -W 2 10.50.0.10
```

Blocked connections — these should show 100% packet loss:

```sh
# Guest phone -> Camera
docker compose exec phone_guest ping -c 3 -W 2 10.30.0.10

# Smart TV -> NAS
docker compose exec SmartTV ping -c 3 -W 2 10.50.0.10

# NAS -> Laptop
docker compose exec nas ping -c 3 -W 2 10.10.0.10
```

To test access to a web application instead of using ping:

```sh
# Laptop -> Camera: expected HTTP 200 (login page)
docker compose exec laptop python -c 'import urllib.request; print(urllib.request.urlopen("http://10.30.0.10:5000/", timeout=3).status)'

# Guest phone -> Camera: expected timeout error
docker compose exec phone_guest python -c 'import urllib.request; print(urllib.request.urlopen("http://10.30.0.10:5000/", timeout=3).status)'
```

HTTP 200 here means the login page is reachable, not that authentication succeeded. Connections through the host's `localhost` ports do not test filtering between devices.

## View connection attempts on the router

Open **http://localhost:5006** and sign in with the router administrator account:

- Username: `admin`
- Initial password: `router123`

Change these credentials in `ROUTER_ADMIN` in `config/devices_config.py`, then run `docker compose restart router`.

The router page has two views:

- **Authentication attempts:** password and MFA attempts from all five devices, including successes, failures, lockouts, and SMTP errors. Filter by device or result, refresh, and use pagination for older entries. Each entry includes the UTC timestamp, source IP, username, authentication step, and HTTP status. Passwords and MFA codes are never recorded as fields.
- **Firewall traffic:** the latest allowed and blocked packets, with source and destination IPs. Network permission does not imply successful authentication.

The central journal is stored in `/var/lib/router/connections.sqlite3`, in the `router_logs` Docker volume mounted only on the router. Each device has its own persistent delivery queue and retries automatically if the router is unavailable. Authentication logs survive container restarts and recreation; `docker compose down -v` deletes the volumes. Firewall traffic still uses `/var/log/fw.log` and is lost when the router container is recreated.

Only the router administrator page provides access to these logs through the applications; device pages and the write-only collection endpoint cannot read them. An administrator with Docker access can still inspect the underlying files.
