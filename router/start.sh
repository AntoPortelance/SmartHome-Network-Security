#!/bin/sh
set -eu

echo "Starting Smart Home Router..."

# Load firewall
nft -f /etc/firewall.nft

echo "IP forwarding enabled."
echo "Firewall loaded."
echo "Starting firewall logger..."

# Supervise both services so a logger or dashboard failure restarts the router.
exec python /app/supervisor.py
