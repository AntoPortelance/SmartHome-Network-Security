from flask import Flask, render_template
from mfa import configure_mfa

app = Flask(__name__)
configure_mfa(app, "laptop", "Laptop", lambda **context: render_template("login.html", **context))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
