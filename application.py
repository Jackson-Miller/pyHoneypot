import os
import secrets
from datetime import datetime, timedelta
from forms import LoginForm
from authlib.integrations.flask_client import OAuth
from azure.data.tables import TableServiceClient
from azure.core.credentials import AzureNamedKeyCredential
from flask import Flask, flash, redirect, request, render_template, url_for
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user


def write_storage_table(username, password, ip):
    entity = {
        "PartitionKey": "honeypot",
        "RowKey": str(secrets.token_hex(16)),
        "DateTime": datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "Username": username,
        "Password": password,
        "IPAddress": ip
    }

    credential = AzureNamedKeyCredential(os.environ["AZ_STORAGE_ACCOUNT"], os.environ["AZ_STORAGE_KEY"])
    service = TableServiceClient(endpoint=os.environ["AZ_STORAGE_ENDPOINT"], credential=credential)
    client = service.get_table_client(table_name=os.environ["AZ_STORAGE_TABLE"])
    client.create_entity(entity=entity)
    client.close()
    service.close()


def read_storage_table(query_filter):
    credential = AzureNamedKeyCredential(os.environ["AZ_STORAGE_ACCOUNT"], os.environ["AZ_STORAGE_KEY"])
    service = TableServiceClient(endpoint=os.environ["AZ_STORAGE_ENDPOINT"], credential=credential)
    client = service.get_table_client(table_name=os.environ["AZ_STORAGE_TABLE"])
    entities = client.query_entities(query_filter=query_filter)
    client.close()
    service.close()

    return entities


def remove_storage_entity(partitionkey, rowkey):
    credential = AzureNamedKeyCredential(os.environ["AZ_STORAGE_ACCOUNT"], os.environ["AZ_STORAGE_KEY"])
    service = TableServiceClient(endpoint=os.environ["AZ_STORAGE_ENDPOINT"], credential=credential)
    client = service.get_table_client(table_name=os.environ["AZ_STORAGE_TABLE"])
    client.delete_entity(partitionkey, rowkey)
    client.close()
    service.close()


def get_user(user_json=None, user_id=None):
    query_filter = ""
    user_data = ""
    if user_json:
        query_filter = f"PartitionKey eq 'users' and id eq \'{user_json['oid']}\'"
    else:
        query_filter = f"PartitionKey eq 'users' and id eq '{user_id}'"
    user_records = read_storage_table(query_filter)
    for user_record in user_records:
        user_data = User(
            id=user_record['id'],
            name=user_record['name'],
            email=user_record['email'],
            role=user_record['role']
        )

    if user_data:
        return user_data
    else:
        return None


app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ["SECRET_KEY"]
app.config.update(
    SESSION_COOKIE_NAME="__Host-session",
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Strict',
)
login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.session_protection = "strong"
login_manager.init_app(app)
oauth = OAuth(app)
oauth.register(
    name='azure',
    client_id=os.environ["CLIENT_ID"],
    client_secret=os.environ["CLIENT_SECRET"],
    redirect_uri="https://admin.thejacksonmiller.com/callback",
    server_metadata_url=os.environ["OIDC_METADATA"],
    client_kwargs={
        'scope': 'openid email profile'
    }
)


class User(UserMixin):
    def __init__(self, id, name, email, role):
        self.id = id
        self.name = name
        self.email = email
        self.role = role

    @staticmethod
    def get(user_id):
        return get_user(user_id=user_id)


@login_manager.user_loader
def load_user(userid):
    return User.get(userid)


@app.after_request
def add_security_headers(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'; style-src 'self' https://*.jsdelivr.net; " \
                                                  "script-src-elem 'self' https://*.jsdelivr.net "
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
    return redirect(url_for("login"))


@app.route("/results")
@login_required
def results():
    table = read_storage_table("PartitionKey eq 'honeypot'")
    return render_template("results.html", data=table, current_user=current_user)


@app.route("/delete/<rowkey>")
@login_required
def delete(rowkey):
    remove_storage_entity("honeypot", rowkey)
    return redirect(url_for("results"))


@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        name = request.form["username"]
        password = request.form["password"]
        ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
        if name.lower() == os.environ["ADMIN_ACCOUNT"].lower():
            redirect_uri = url_for('callback', _external=True)
            return oauth.azure.authorize_redirect(redirect_uri)
        else:
            write_storage_table(name, password, ip)

        flash("Invalid username or password.")
    else:
        pass
        # flash(form.errors)

    return render_template("index.html", form=form)


@app.route('/callback')
def callback():
    token = oauth.azure.authorize_access_token()
    user_details = token.get('userinfo')
    user = get_user(user_details)
    if user:
        cookie_duration = timedelta(hours=1)
        login_user(user=user, duration=cookie_duration)
        return redirect(url_for("results"))
    else:
        return redirect(url_for("login"))


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))


if __name__ == "__main__":
    app.run()
