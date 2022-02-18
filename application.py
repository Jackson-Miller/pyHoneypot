import os
import secrets
from forms import LoginForm
from azure.core.credentials import AzureNamedKeyCredential
from azure.data.tables import TableServiceClient
from flask import Flask, flash, redirect, request, render_template, url_for

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


@app.route("/")
def home():
    form = LoginForm(request.form)
    return render_template("index.html", form=form)


@app.route("/login", methods=["POST"])
def login():
    name = request.form["username"]
    password = request.form["password"]
    ip = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
    write_storage_table(name, password, ip)

    flash("Invalid username or password.")
    return redirect(url_for("home"))


if __name__ == "__main__":
    app.run()
