import flask_bcrypt
import datetime

from cryptography.fernet import Fernet
from flask import Flask, render_template, request, redirect, url_for, session, flash, abort
from flask_mysqldb import MySQL
import MySQLdb.cursors
import re
import requests, json, pathlib
import os
from pip._vendor import cachecontrol
import google.auth.transport.requests
from google_auth_oauthlib.flow import Flow
from google.oauth2 import id_token
from flask_bcrypt import Bcrypt

bcrypt = Bcrypt()
app = Flask(__name__)
datetime = datetime.datetime.now()

if __name__ == ' main ':
    app.run()

# Change this to your secret key (can be anything, it's for extra protection)
app.secret_key = 'Maomaox31'
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

# Enter your database connection details below
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'melvin'
app.config['MYSQL_DB'] = 'pythonlogin'

GOOGLE_CLIENT_ID = "1019735437864-5h23ehvveeut9euf3ls9j1gqamhbm4k1.apps.googleusercontent.com"
client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "client_secret.json")
flow = Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email",
            "openid"],
    redirect_uri="http://127.0.0.1:5000/callback"
)




def login_is_required(function):
    def wrapper(*args, **kwargs):
        if "google_id" not in session:
            return abort(401)  # Authorization required
        else:
            return function()

    return wrapper


def is_human(captcha_response):
    """ Validating recaptcha response from google server.
        Returns True captcha test passed for the submitted form
        else returns False.
    """
    secret = "6LdS-vogAAAAAPWpUP2shWczeyqzXS1OtI0XQLsP"
    payload = {'response': captcha_response, 'secret': secret}
    response = requests.post("https://www.google.com/recaptcha/api/siteverify", payload)
    response_text = json.loads(response.text)
    return response_text['success']


# Intialize MySQL
mysql = MySQL(app)


# http://localhost:5000/MyWebApp/ - this will be the login page, we need to use both GET and POST
# requests

@app.route('/')
def base():
    return render_template('index1.html')


@app.route("/google_login")
def google_login():
    authorization_url, state = flow.authorization_url()
    session["state"] = state
    return redirect(authorization_url)


@app.route('/MyWebApp/', methods=['GET', 'POST'])
def login():
    # Output message if something goes wrong...
    msg = ''
    # Check if "username" and "password" POST requests exist (user submitted form)
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        # Create variables for easy access
        username = request.form['username']
        password = request.form['password']

        # Check if account exists using MySQL
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE username = %s ', (username,))
        # Fetch one record and return result
        account = cursor.fetchone()
        user_hashpwd = account['password']
        bcrypt = Bcrypt()
        if bcrypt.check_password_hash(user_hashpwd, password):
            # Create session data, we can access this data in other routes
            session['loggedin'] = True
            session['id'] = account['id']
            session['username'] = account['username']
            # Redirect to 2FA
            return redirect("/MyWebApp/index")

    else:
        # Account doesn’t exist or username/password incorrect
        msg = 'Incorrect username/password!'
    # Show the login form with message (if any)
    return render_template('index_login.html', msg='')


@app.route('/MyWebApp/register', methods=['GET', 'POST'])
def register():
    sitekey = "6LdS-vogAAAAAKoyS9QGjo0ZTJLraQB8XEb6Ess9"
    # Output message if something goes wrong...
    msg = ''
    # Check if "username", "password" and "email" POST requests exist (user submitted form)
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'email' in request.form:
        # Create variables for easy access
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        hashpwd = bcrypt.generate_password_hash(password)
        # captcha_response = request.form['g-recaptcha-response']
        if True:  # is_human(captcha_response): # FIX
            # Check if account exists using MySQL
            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute('SELECT * FROM accounts WHERE username = %s', (username,))
            account = cursor.fetchone()
            # If account exists show error and validation checks
            if account:
                msg = 'Account already exists!'
            elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
                msg = 'Invalid email address!'
            elif not re.match(r'[A-Za-z0-9]+', username):
                msg = 'Username must contain only characters and numbers!'
            elif not username or not password or not email:
                msg = 'Please fill out the form!'
            else:
                # Account doesnt exists and the form data is valid, now insert new account into accounts table
                cursor.execute('INSERT INTO accounts VALUES (NULL, %s, %s, %s, 0)',
                               (username, hashpwd, email,))
                mysql.connection.commit()
                msg = 'You have successfully registered!'
        else:
            # Log invalid attempts
            flash("Sorry ! Bots are not allowed.")

    # Show registration form with message (if any)
    return render_template('register.html', msg=msg, sitekey=sitekey)


@app.route("/callback")
def callback():
    flow.fetch_token(authorization_response=request.url)

    if not session["state"] == request.args["state"]:
        abort(500)  # State does not match!

    credentials = flow.credentials
    request_session = requests.session()
    cached_session = cachecontrol.CacheControl(request_session)
    token_request = google.auth.transport.requests.Request(session=cached_session)

    id_info = id_token.verify_oauth2_token(
        id_token=credentials._id_token,
        request=token_request,
        audience=GOOGLE_CLIENT_ID
    )

    session["google_id"] = id_info.get("sub")
    session["name"] = id_info.get("name")
    session["google_email"]= id_info.get("google_email")
    return redirect("/MyWebApp/index")


@app.route('/MyWebApp/index')
def index():
    # Check if user is loggedin
    if 'loggedin' in session:
        # User is loggedin show them the home page
        return render_template('index.html', username=session['username'])
    elif "google_id" in session:
        return render_template('index.html')
    # User is not loggedin redirect to login page
    return redirect(url_for('login'))


@app.route('/MyWebApp/about')
def about():
    return render_template('about.html')


@app.route('/MyWebApp/points')  # TODO actions for points
def points():
    return render_template('points.html')


@app.route('/MyWebApp/rewards')
def rewards():
    rewards_available = [
        # https://i.pinimg.com/736x/8a/62/bb/8a62bbf382928fe1993445cf0a69cc4a--card-ui-ui-animation.jpg
        {"title": "Grab Gift Card", "img": "https://cdn.worldvectorlogo.com/logos/grab.svg", "price": "$5 (5,000 pts)"},
        {"title": "Grab Gift Card", "img": "https://cdn.worldvectorlogo.com/logos/grab.svg", "price": "$10 (10,000 pts)"},
        {"title": "Spotify 1 Month Premium", "img": "https://cdn.worldvectorlogo.com/logos/spotify-2.svg", "price": "$5 (5,000 pts)"},
        {"title": "Apple Gift Card", "img": "https://cdn.worldvectorlogo.com/logos/apple1.svg", "price": "$25 (25,000 pts)"},
        {"title": "Google Play Gift Card", "img": "https://cdn.worldvectorlogo.com/logos/google-play-5.svg", "price": "$10 (10,000 pts)"},
    ]
    return render_template('rewards.html', rewards=rewards_available)


@app.route('/MyWebApp/account')
def account():
    return render_template('account.html')


@app.route('/MyWebApp/index1')
def index1():
    session.pop('loggedin', None)
    session.pop('id', None)
    session.pop('username', None)
    session.clear()
    return render_template('index1.html')


@app.route('/MyWebApp/profile')
def profile():
    # Check if user is loggedin
    if 'loggedin' in session:
        # We need all the account info for the user so we can display it on the profile page
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE id = %s', (session['id'],))
        account = cursor.fetchone()
        # Show the profile page with account info
        return render_template('profile.html', account=account)

    elif "google_id" in session:
        return render_template('profile_google.html')
    # User is not loggedin redirect to login page
    return redirect(url_for('login'))


@app.route('/MyWebApp/ranking')
def ranking():
    if 'loggedin' not in session:
        return redirect(url_for('login'))

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT * FROM accounts ORDER BY points DESC")

    rankings_list = cursor.fetchmany(10)
    return render_template('ranking.html', rankings=rankings_list)


if __name__ == '__main__':
    app.run(debug=True)