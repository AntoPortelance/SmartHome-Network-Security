import subprocess

from flask import Flask, abort, redirect, request, render_template, url_for
from devices_config import DEVICES
from mfa import configure_mfa

app = Flask(__name__)


def render_page(**context):
    return render_template(
        "login.html",
        devices={name: device for name, device in DEVICES.items() if name != "nas"},
        **context,
    )


configure_mfa(app, "nas", "NAS", render_page)


@app.post("/ping")
def ping():
    if not app.extensions["is_authenticated"]():
        return redirect(url_for("login"))
    target = request.form.get("ip")
    targets = {device["ip"] for name, device in DEVICES.items() if name != "nas"}
    if target not in targets:
        abort(400, description="Choose a configured device.")
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", "1", target],
            capture_output=True, text=True, timeout=3,
        )
        output = result.stdout + result.stderr
        status = "Device reachable" if result.returncode == 0 else "No reply (blocked or unavailable)"
    except subprocess.TimeoutExpired:
        output = "Ping timed out."
        status = "No reply (blocked or unavailable)"
    return render_page(ping_output=output, ping_status=status, selected_ip=target)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
