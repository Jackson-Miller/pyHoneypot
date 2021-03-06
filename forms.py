from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired


class LoginForm(FlaskForm):
    username = StringField("Username", id="floatingInput", validators=[DataRequired()])
    password = PasswordField("Password", id="floatingPassword", validators=[DataRequired()])
    submit = SubmitField("Sign in")
