from flask import Flask, render_template, request, make_response
from subprocess import check_output

import flask_login
from flask import Flask, render_template, request, make_response
from flask_login import login_required
from passlib.hash import sha256_crypt
from wtforms import Form, StringField, PasswordField, validators
from wtforms.widgets import TextArea
from flask_wtf.csrf import CsrfProtect, CSRFProtect

Users = {}


class RegistrationForm(Form):
    username = StringField('Username', [validators.Length(min=4, max=25)])
    password = PasswordField('New Password', [
        validators.DataRequired(),
        validators.length(min=6, max=20)
    ])
    mfa = StringField('mfa', [validators.DataRequired(), validators.Length(min=10, max=20)])


class UserLoginForm(Form):
    username = StringField('Username', [validators.DataRequired()])
    password = PasswordField('Password', [validators.DataRequired()])
    mfa = StringField('mfa', [validators.DataRequired()])


class SpellCheckForm(Form):
    inputtext = StringField(u'inputtext', widget=TextArea())


app = Flask(__name__)
app.config['SESSION_TYPE'] = 'memcached'
app.config['SECRET_KEY'] = 's3cr3t'

csrf = CSRFProtect()
# csrf.init_app(app)


login_manager = flask_login.LoginManager()
login_manager.init_app(app)


# CSRF Protect


class User(flask_login.UserMixin):
    pass
    # @self.is_authenticated.setter
    # def is_authenticated(self, value):
    # self.is_authenticated = value


@login_manager.user_loader
def user_loader(username):
    if username not in Users:
        return
    user = User()
    user.id = username
    return user


@login_manager.request_loader
def request_loader(username):
    if username not in Users:
        return
    user = User()
    user.id = username
    return user


@app.route('/')
@app.route('/index')
def mainpage(user=None):
    user = user
    return render_template('index.html', user=user)


@app.route('/register', methods=['GET', 'POST'])
def register():
    success = None
    form = RegistrationForm(request.form)
    if request.method == 'POST' and form.validate():
        username = form.username.data
        password = sha256_crypt.encrypt(form.password.data)
        mfa = form.mfa.data
        if username in Users:
            success = 'failure'
            return render_template('register.html', form=form)
        Users[username] = {'password': password, 'mfa': mfa}
        success = 'success'

        # return redirect('/login')

    return render_template('register.html', form=form, success=success)


@app.route('/login', methods=['GET', 'POST'])
def login():
    result = None
    form = UserLoginForm(request.form)
    if request.method == 'POST':
        username = form.username.data
        password = form.password.data
        mfa = form.mfa.data
        if (username not in Users):
            result = 'incorrect'
            return render_template('login.html', form=form)
        if (not sha256_crypt.verify(password, Users[username]['password'])):
            result = "incorrect"
            return render_template('login.html', form=form)
        if (mfa != Users[username]['mfa']):
            result = 'Two-factor failure'
            return render_template('login.html', form=form)
        user = User()
        user.id = username
        flask_login.login_user(user)
        result = 'success'
        # return redirect('/spell_check')

    return render_template('login.html', form=form, result=result)


@app.route('/spell_check', methods=['GET', 'POST'])
@login_required
def spell_check():
    textout = None
    misspelled = None
    form = SpellCheckForm(request.form)
    if request.method == 'POST':
        inputtext = form.inputtext.data
        textout = inputtext
        with open("words.txt", "w") as fo:
            fo.write(inputtext)
        output = (check_output(["./a.out", "words.txt", "wordlist.txt"], universal_newlines=True))
        misspelled = output.replace("\n", ", ").strip().strip(',')
    response = make_response(render_template('spell_check.html', form=form, textout=textout, misspelled=misspelled))
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    return response
