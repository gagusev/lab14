from flask import Flask, render_template, url_for, redirect, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, IntegerField, FileField
from wtforms.validators import InputRequired, Length, EqualTo, ValidationError
from flask_bcrypt import Bcrypt
from werkzeug.utils import secure_filename
import re, os 

app = Flask(__name__)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'thisisasecretkey'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

email_regex = re.compile(r"[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?")


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    email = db.Column(db.String(40), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)
    is_admin = db.Column(db.Boolean, nullable=False)

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    prod_type = db.Column(db.String(50), nullable=False)
    name = db.Column(db.String(50), nullable=False)
    info = db.Column(db.String(1024), nullable=True)
    manufacturer = db.Column(db.String(50), nullable=False)
    price = db.Column(db.Integer, nullable=False)
    pic = db.Column(db.String(100), nullable=False)

class Review(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    prod_id = db.Column(db.Integer, nullable=False)
    rating = db.Column(db.Integer, nullable=False)

class RegisterForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=6, max=20)], render_kw={"placeholder": "Username"})

    email = StringField(validators=[
                             InputRequired(), Length(min=8, max=40)], render_kw={"placeholder": "E-mail"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=80), EqualTo('re_password', message='Passwords must match.')], render_kw={"placeholder": "Password"})

    re_password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=80)], render_kw={"placeholder": "Password Repeat"})

    submit = SubmitField('Register')

    def validate_username(self, username):
        if not username.data[0].isalpha():
            raise ValidationError(
                'Username can only start with a letter. Please choose a different one.')
        for sym in username.data:
            if sym.isalpha() or sym.isnumeric() or sym == '_':
                pass
            else:
                raise ValidationError(
                    'Prohibited characters are being used. Please choose a different one.')
        existing_user_username = User.query.filter_by(
            username=username.data).first()
        if existing_user_username:
            raise ValidationError(
                'That username already exists. Please choose a different one.')

    def validate_email(self, email):
        if not email_regex.match(email.data):
            raise ValidationError(
                'That E-mail does not seem to match any pattern. Please choose a different one.')
        existing_user_email = User.query.filter_by(
            email=email.data).first()
        if existing_user_email:
            raise ValidationError(
                'That E-mail is already taken. Please choose a different one.')
    
    def validate_password(self, password):
        foundUpper = False
        foundLower = False
        foundNumber = False
        foundSpecsym = False
        Specsym = '%$#@&*^|\/~[{]}'
        for sym in password.data:
            if sym.isupper():
                foundUpper = True
            if sym.islower():
                foundLower = True
            if sym.isnumeric():
                foundNumber = True
            if sym in Specsym:
                foundSpecsym = True
        if not foundUpper:
            raise ValidationError('Password must have at least one upper-case character.')
        if not foundLower:
            raise ValidationError('Password must have at least one lower-case character.')
        if not foundNumber:
            raise ValidationError('Password must have at least one digit.')
        if not foundSpecsym:
            raise ValidationError('Password must have at least one special character.')

class LoginForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=1, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=1, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Login')

class CreateForm(FlaskForm):

    prod_type = StringField(validators=[InputRequired(), Length(max=50)], render_kw={"placeholder": "Product type"})
    name = StringField(validators=[InputRequired(), Length(max=50)], render_kw={"placeholder": "Product name"})
    info = TextAreaField(validators=[InputRequired(), Length(max=1024)], render_kw={"placeholder": "Information about product"})
    manufacturer = StringField(validators=[InputRequired(), Length(max=50)], render_kw={"placeholder": "Manufacturer"})
    price = IntegerField(validators=[InputRequired()], render_kw={"placeholder": "Price"})
    pic = StringField(validators=[InputRequired(), Length(max=300)], render_kw={"placeholder": "Picture URL"})

    submit = SubmitField('Register product')


@app.route('/')
def home():
    return render_template('home.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))
    return render_template('login.html', form=form)


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    return render_template('dashboard.html')


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password, email=form.email.data, is_admin=False)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html', form=form)

@app.route('/add', methods=['GET', 'POST'])
@login_required
def add_prod():
    if current_user.is_admin:
        form = CreateForm()

        if form.validate_on_submit():
            new_product = Product(prod_type=form.prod_type.data, name=form.name.data, info=form.info.data,
                                    manufacturer=form.manufacturer.data, price=form.price.data, pic=form.pic.data)
            db.session.add(new_product)
            db.session.commit()
            return redirect(url_for('catalogue'))

        return render_template('add.html', form=form)
    else:
        return '<h1>Oops, only admins are capable of adding products!<h1>'

@app.route('/catalogue', methods=['GET', 'POST'])
def catalogue():
    with app.app_context():
        res = db.engine.execute('SELECT * FROM product')
    return render_template('catalogue.html', products=res.all())


if __name__ == "__main__":
    app.run(debug=True)
