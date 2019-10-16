from flask import Flask, render_template, request, redirect
from wtforms import Form, BooleanField, StringField, PasswordField, validators
from wtforms.widgets import TextArea
from passlib.hash import sha256_crypt
import flask_login
from flask_login import LoginManager, login_required, login_user, logout_user, current_user
import subprocess
from subprocess import check_output
from flask_wtf.csrf import CSRFProtect

# User Variable to store entries
Users = {}


class RegistrationForm(Form):
    username = StringField('Username', [validators.Length(min=4, max=25)])
    password = PasswordField('New Password', [
        validators.DataRequired(),
        validators.length(min=6, max=20)
    ])
    mfa = StringField('mfa', [validators.DataRequired(), validators.Length(min=10, max=20)])
    # success = StringField('success', id='success')


class UserLoginForm(Form):
    username = StringField('Username', [validators.DataRequired()])
    password = PasswordField('Password', [validators.DataRequired()])
    mfa = StringField('mfa', [validators.DataRequired()])
    result = StringField('result')


class SpellCheckForm(Form):
    inputtext = StringField(u'inputtext', widget=TextArea())
    textout = StringField(u'textout', widget=TextArea())
    misspelled = StringField(u'misspelled', widget=TextArea())


app = Flask(__name__)
app.config['SESSION_TYPE'] = 'memcached'
app.config['SECRET_KEY'] = 'super secret key'

# Login Manager
login_manager = flask_login.LoginManager()
login_manager.init_app(app)


# CSRF Protect
# csrf = CSRFProtect(app)

class User(flask_login.UserMixin):
    pass


@login_manager.user_loader
def user_loader(username):
    if username not in Users:
        return
    user = User()
    user.id = username
    return user


@login_manager.request_loader
def request_loader(request):
    username = request.form.get('username')
    if username not in Users:
        return
    user = User()
    user.id = username
    user.is_authenticated = sha256_crypt.verify(password, Users[username]['password'])


@app.route('/')
@app.route('/index')
def mainpage(user=None):
    user = user
    return render_template('index.html', user=user)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm(request.form)
    if request.method == 'POST' and form.validate():
        username = form.username.data
        password = sha256_crypt.encrypt(form.password.data)
        mfa = form.mfa.data
        if username in Users:
            form.username.data = 'user already exists'
            return reinder_template('register.html', form=form)
        Users[username] = {'password': password, 'mfa': mfa}
        # return redirect('/login')
        # form.success.data = 'success'
    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = UserLoginForm(request.form)
    if request.method == 'POST':
        username = form.username.data
        password = form.password.data
        mfa = form.mfa.data
        if (username not in Users):
            form.result.data = "incorrect"
            return render_template('login.html', form=form)
        if (not sha256_crypt.verify(password, Users[username]['password'])):
            form.result.data = "incorrect"
            return render_template('login.html', form=form)
        if (mfa != Users[username]['mfa']):
            form.result.data = "Two-factor failure"
            return render_template('login.html', form=form)
        user = User()
        user.id = username
        flask_login.login_user(user)
        form.result.data = "success"
        # return redirect('/spell_check')
    return render_template('login.html', form=form)


@app.route('/spell_check', methods=['GET', 'POST'])
@login_required
def spell_check():
    form = SpellCheckForm(request.form)
    if request.method == 'POST':
        inputtext = form.inputtext.data
        form.textout.data = inputtext
        with open("words.txt", "w") as fo:
            fo.write(inputtext)
        output = (check_output(["./a.out", "words.txt", "wordlist.txt"], universal_newlines=True))
        form.misspelled.data = output.replace("\n", ", ").strip().strip(',')
    response = make_response(render_template('spell_check.html', form=form))
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    return response
