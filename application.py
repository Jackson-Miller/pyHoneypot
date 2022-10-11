import os
import secrets
from datetime import datetime, timedelta
from forms import LoginForm
from authlib.integrations.flask_client import OAuth
from azure.data.tables import TableServiceClient, UpdateMode
from azure.core.credentials import AzureNamedKeyCredential
from flask import Flask, flash, redirect, request, render_template, url_for
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user


def write_storage_table(entity):
    credential = AzureNamedKeyCredential(os.environ["AZ_STORAGE_ACCOUNT"], os.environ["AZ_STORAGE_KEY"])
    service = TableServiceClient(endpoint=os.environ["AZ_STORAGE_ENDPOINT"], credential=credential)
    client = service.get_table_client(table_name=os.environ["AZ_STORAGE_TABLE"])
    client.create_entity(entity=entity)
    client.close()
    service.close()


def update_storage_table(entity):
    credential = AzureNamedKeyCredential(os.environ["AZ_STORAGE_ACCOUNT"], os.environ["AZ_STORAGE_KEY"])
    service = TableServiceClient(endpoint=os.environ["AZ_STORAGE_ENDPOINT"], credential=credential)
    client = service.get_table_client(table_name=os.environ["AZ_STORAGE_TABLE"])
    client.update_entity(mode=UpdateMode.MERGE, entity=entity)
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
    SESSION_COOKIE_SAMESITE='Lax',
)
login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.session_protection = "strong"
login_manager.init_app(app)
oauth = OAuth(app)
oauth.register(
    name='oidc',
    client_id=os.environ["CLIENT_ID"],
    client_secret=os.environ["CLIENT_SECRET"],
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
                                                  "script-src-elem 'self' https://*.jsdelivr.net " \
                                                  "https://static.cloudflareinsights.com "
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
    pw_table = read_storage_table("PartitionKey eq 'honeypot'")
    uri_table = read_storage_table("PartitionKey eq 'uri'")
    return render_template("results.html", pw_data=pw_table, uri_data=uri_table, current_user=current_user)


@app.route("/delete/<table>/<rowkey>")
@login_required
def delete(table, rowkey):
    remove_storage_entity(table, rowkey)
    return redirect(url_for("results"))


@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        name = request.form["username"]
        password = request.form["password"]
        ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
        if name.lower() == os.environ["ADMIN_ACCOUNT"].lower():
            redirect_uri = url_for("callback", _external=True, _scheme="https")
            return oauth.oidc.authorize_redirect(redirect_uri, login_hint=name)
        else:
            entity = {
                "PartitionKey": "honeypot",
                "RowKey": str(secrets.token_hex(16)),
                "DateTime": datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ"),
                "Username": name,
                "Password": password,
                "IPAddress": ip
            }
            write_storage_table(entity)

        flash("Invalid username or password.")
    else:
        pass

    return render_template("index.html", form=form)


@app.route('/callback')
def callback():
    token = oauth.oidc.authorize_access_token()
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
    metadata = oauth.oidc.load_server_metadata()
    end_session_endpoint = metadata.get('end_session_endpoint')
    redirect_uri = url_for("home", _external=True, _scheme="https")
    logout_uri = f"{end_session_endpoint}?post_logout_redirect_uri={redirect_uri }"
    logout_user()
    return redirect(logout_uri)


@app.errorhandler(404)
def page_not_found(e):
    url_data = ""
    url = request.url
    url_results = read_storage_table(f"PartitionKey eq 'uri' and URL eq '{url}'")

    for url_result in url_results:
        url_data = url_result
    if url_data:
        url_data["Count"] = url_data["Count"] + 1
        url_data["DateTimeLastAccessed"] = datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
        update_storage_table(url_data)
    else:
        entity = {
            "PartitionKey": "uri",
            "RowKey": str(secrets.token_hex(16)),
            "DateTimeLastAccessed": datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "URL": url,
            "Count": 1
        }
        write_storage_table(entity)
    return render_template('404.html'), 404


@app.errorhandler(400)
def bad_request(e):
    return render_template('400.html'), 400


if __name__ == "__main__":
    app.run()
