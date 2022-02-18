from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField
from wtforms.validators import DataRequired


class LoginForm(FlaskForm):
    username = StringField('username', id="floatingInput", validators=[DataRequired()])
    password = PasswordField('Password', id="floatingPassword", validators=[DataRequired()])
