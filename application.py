import os
import secrets
from forms import LoginForm
from azure.core.credentials import AzureNamedKeyCredential
from azure.data.tables import TableServiceClient
from flask import Flask, flash, jsonify, redirect, request, render_template, url_for

credential = AzureNamedKeyCredential(os.environ["AZ_STORAGE_ACCOUNT"], os.environ["AZ_STORAGE_KEY"])


def write_storage_table(username, password, ip):
    entity = {
        "PartitionKey": "honeypot",
        "RowKey": str(secrets.token_hex(16)),
        "Username": username,
        "Password": password,
        "IPAddress": ip
    }
    service = TableServiceClient(endpoint=os.environ["AZ_STORAGE_ENDPOINT"], credential=credential)
    client = service.get_table_client(table_name=os.environ["AZ_STORAGE_TABLE"])
    entity_results = client.create_entity(entity=entity)
    client.close()
    service.close()


app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ["SECRET_KEY"]
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
)


@app.after_request
def add_security_headers(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'; style-src 'self' https://*.jsdelivr.net;"
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'accelerometer=(), autoplay=(), camera=(), cross-origin-isolated=(), ' \
                                             'display-capture=(), document-domain=(), encrypted-media=(), ' \
                                             'fullscreen=(), geolocation=(), gyroscope=(), keyboard-map=(), ' \
                                             'magnetometer=(), microphone=(), midi=(), payment=(), ' \
                                             'picture-in-picture=(), publickey-credentials-get=(), ' \
                                             'screen-wake-lock=(), sync-xhr=(), usb=(), web-share=(), ' \
                                             'xr-spatial-tracking=()'
    return response


@app.route("/")
def home():
    form = LoginForm(request.form)
    return render_template("index.html", form=form)


@app.route("/login", methods=["POST"])
def login():
    name = request.form["username"]
    password = request.form["password"]
    ip = request.remote_addr
    print(ip)
    write_storage_table(name, password, ip)

    flash("Invalid username or password.")
    return redirect(url_for("home"))


if __name__ == "__main__":
    app.run(debug=True)
