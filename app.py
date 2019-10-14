from flask import Flask, render_template, redirect, url_for
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import os
import subprocess

app = Flask(__name__)
app.config['SECRET_KEY'] = 'S3cr3t$'
bootstrap = Bootstrap(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class LoginForm(FlaskForm):
    uname = StringField('uname', validators=[InputRequired(), Length(min=4, max=15)])
    pword = PasswordField('pword', validators=[InputRequired(), Length(min=8, max=80)])


class Spell_checkForm(FlaskForm):
    words = StringField('Enter text for Spell Check', validators=[InputRequired(), Length(min=3, max=50)])


class RegisterForm(FlaskForm):
    email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    uname = StringField('uname', validators=[InputRequired(), Length(min=4, max=15)])
    pword = PasswordField('pword', validators=[InputRequired(), Length(min=8, max=80)])


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = form.uname.data
        for line in open("userfile.txt", "r").readlines():
            login_info = line.split()
            if user == login_info[0] and check_password_hash(login_info[1], form.pword.data):
                form.pword.data = 'success'
            else:
                form.pword.data = "failure"




    return render_template('login.html', form=form)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.pword.data, method='sha256')
        file = open("userfile.txt", "a")
        file.write(form.uname.data)
        file.write(" ")
        file.write(hashed_password)
        file.write("\n")
        # new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)

        return '<h1>New user has been created!</h1>'
        # return '<h1>' + form.username.data + ' ' + form.email.data + ' ' + form.password.data + '</h1>'

    return render_template('signup.html', form=form)


@app.route('/spell_check', methods=['GET', 'POST'])
# @login_required
def spell_check():
    form = Spell_checkForm()

    if form.validate_on_submit():
        spell = form.words.data
        with open("word.txt", "w") as f:
            print(spell, file=f)
            output = subprocess.run(["./a.out", "word.txt", "wordlist.txt"], check=True, stdout=subprocess.PIPE,
                                    universal_newlines=True)
            result = output.stdout
            with open("output.txt", "w+") as k:
                print(result, file=k)
                k.close()
                with open('output.txt', 'r') as j:
                    for line in j:
                        for word in line.split():
                            return word

    return render_template('spellcheck.html', form=form)


@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', name=current_user.username)


if __name__ == '__main__':
    app.run(debug=True)