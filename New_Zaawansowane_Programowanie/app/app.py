import datetime
import io
import os
import re

from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user
from flask_swagger_ui import get_swaggerui_blueprint
from flask import Flask, flash, request, render_template, redirect, url_for, send_file
from flask_restful import Api
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from PIL import Image, ImageOps
from wtforms.validators import InputRequired, Length, ValidationError
from datetime import datetime

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}
### swagger specific ###
SWAGGER_URL = '/swagger'
API_URL = '/static/swagger.json'
SWAGGERUI_BLUEPRINT = get_swaggerui_blueprint(SWAGGER_URL, API_URL, config={
    'app_name': "Zaawansowane Programowanie w Pythonie"})


app = Flask(__name__)
bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'habababa'
app.config['PRESERVE_CONTEXT_ON_EXCEPTION'] = False
app.register_blueprint(SWAGGERUI_BLUEPRINT)
db = SQLAlchemy(app)
# with app.app_context():
#     db.create_all()

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
# api = Api(app)


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)


class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "login"})
    password = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "hasło"})
    submit = SubmitField("Rejestracja")

    def validate_if_user_exists(self, username):
        existing_user_username = User.query.filter_by(username=username.data).first()
        if existing_user_username:
            raise ValidationError("Wybrany login jest już zajęty")


class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "login"})
    password = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "hasło"})

    submit = SubmitField("Login")


def check_if_number_is_prime(f_number_to_check: int):
    for i in range(2, f_number_to_check):
        if (f_number_to_check % i) == 0:
            return False
    return True


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route("/")
def main_page():
    return render_template("home.html")


@app.route("/login", methods=['GET', 'POST'])
def login():
    form = LoginForm(request.form)
    if request.method == 'POST':
        if form.validate_on_submit() or (request.form.get("username") is not None and request.form.get("password") is not None):
            user = User.query.filter_by(username=request.form.get("username")).first()
            if user:
                if bcrypt.check_password_hash(user.password, request.form.get("password")):
                    login_user(user)
                    print("Redirect to dashboard page")
                    return render_template('dashboard.html', current_timestamp=datetime.now().time())

    print("Return to login page")
    return render_template("login.html", form=LoginForm())


@app.route("/register", methods=['GET', 'POST'])
def register():
    form = RegisterForm(request.form)
    if request.method == 'POST':
        # if form.username.data and form.password.data:
        if form.validate_on_submit():
            try:
                form.validate_if_user_exists(form.username)
            except:
                return render_template("error.html", error_msg="Użytkownik o podanym loginie istnieje")

            hashed_password = bcrypt.generate_password_hash(form.password.data)
            new_user = User(username=form.username.data, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('login'))
    return render_template("register.html", form=form)


@app.route("/dashboard", methods=['GET', 'POST'])
@login_required
def dashboard():
    return render_template("dashboard.html")


@app.route("/logout", methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/prime/<int:prime_num>', methods=['GET'])
def api_check_prime(prime_num):
    result = {}
    if prime_num is None:
        result["error"] = "Nie podano liczby do sprawdzenia"
        return result
    elif type(prime_num) is not int:
        result["error"] = "Niepoprawny typ. Podaj liczbę całkowitą"
        return result
    result["ifPrime"] = check_if_number_is_prime(int(prime_num))
    return result


@app.route('/checkIfPrime/', methods=['GET', 'POST'])
def api_check_if_prime():
    request_data = request.form
    number_to_check = request_data.get('number_to_check')
    result = {}
    if number_to_check is None:
        result["error"] = "Nie podano liczby do sprawdzenia"
        return result
    elif re.match(r'^([\s\d]+)$', number_to_check) is None:
        result["error"] = "Niepoprawny typ. Podaj liczbę całkowitą"
        return result
    result["ifPrime"] = check_if_number_is_prime(int(number_to_check))
    return result


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/imageInversion', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        # check if the post request has the file part
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        # If the user does not select a file, the browser submits an
        # empty file without a filename.
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            im = Image.open(file)
            im = ImageOps.invert(im.convert('RGB'))
            file_object = io.BytesIO()
            im.save(file_object, "PNG")
            file_object.seek(0)
            return send_file(file_object, mimetype=file.mimetype)

    return render_template("upload_file.html")


if __name__ == '__main__':
    # Ustawiam hosta na 0.0.0.0 i mapuje port -> wymaganie aby aplikacja wstała na heroku!!
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
