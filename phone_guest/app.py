from flask import Flask, g, request, render_template
from devices_config import DEVICES
from audit import configure_audit

app = Flask(__name__)
configure_audit(app, "phone_guest")

# Guest iPhone configuration
iphone = DEVICES["phone_guest"]

USERNAME = iphone["username"]
PASSWORD = iphone["password"]


@app.route("/", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form.get("username")
        password = request.form.get("password")

        if username == USERNAME and password == PASSWORD:
            g.audit_result = "success"
            return render_template(
                "login.html",
                success="iPhone access granted"
            )

        g.audit_result = "invalid_credentials"
        return render_template(
            "login.html",
            error="Invalid username or password"
        )

    return render_template("login.html")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
