import datetime

from cryptography.fernet import Fernet
from flask import Flask, render_template, request, redirect, url_for, session, flash, abort
from flask_mysqldb import MySQL
from Forms import CreateWarehouseForm
import MySQLdb.cursors
import re
import shelve, Inventorys
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


# Change this to your secret key (can be anything, it's for extra protection)
app.secret_key = 'Maomaox31'
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

# Enter your database connection details below
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'ur password in mysql'
app.config['MYSQL_DB'] = 'pythonlogin'

GOOGLE_CLIENT_ID = "1019735437864-5h23ehvveeut9euf3ls9j1gqamhbm4k1.apps.googleusercontent.com"
client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "client_secret.json")
flow = Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email",
            "openid"],
    redirect_uri="http://127.0.0.1:5000/callback"
)

count = 0



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
    return render_template('home1.html')


@app.route("/google_login")
def google_login():
    authorization_url, state = flow.authorization_url()
    session["state"] = state
    return redirect(authorization_url)


@app.route('/MyWebApp/', methods=['GET', 'POST'])
def login():
    # Output message if something goes wrong...
    msg = ''
    global count

    # Check if "username" and "password" POST requests exist (user submitted form)
    try:
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
            status = account["status"]
            if bcrypt.check_password_hash(user_hashpwd, password) and status == "unlock":
                # Create session data, we can access this data in other routes
                session['loggedin'] = True
                session['id'] = account['id']
                session['username'] = account['username']
                # Redirect to 2FA
                return redirect(url_for('home'))

            for count in range(0, 3):
                if account['username'] != username:
                    count = count +1
                    msg = "Incorrect username! Danger"
                    print(count)

                elif account['password'] != password:
                    count = count +1
                    msg = "Incorrect password! Danger"
                    print(count)

                if count == 3:
                    msg = "Account locked"
                    cursor.execute('UPDATE accounts SET status = %s WHERE status = %s', ('locked', status,))
                    mysql.connection.commit()

                else:
                    pass
        else:
            msg = "enter information"
    except(TypeError):
        msg = "Error Try again"
    # Show the login form with message (if any)
    return render_template('index.html', msg=msg)
    # try:
    #     if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
    #         # Create variables for easy access
    #         username = request.form['username']
    #         password = request.form['password']
    #         bcrypt = Bcrypt()
    #         # Check if account exists using MySQL
    #         cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    #         cursor.execute('SELECT * FROM accounts WHERE username = %s AND password = %s', (username,password,))
    #         # Fetch one record and return result
    #         account = cursor.fetchone()
    #         user_hashpwd = account['password']
    #         # status = account["status"]
    #         # count = account["count"]
    #         if account['username'] != username:
    #             msg = ("Incorrect username!", "danger")
    #         elif account['password'] != password:
    #             msg = ("Incorrect password!", "danger")
    #         if bcrypt.check_password_hash(user_hashpwd, password):
    #             #if status ==1:
    #             session['loggedin'] = True
    #             session['id'] = account['id']
    #             session['username'] = account['username']
    #             return redirect(url_for('home'))
    #             #elif status == 0:
    #                 #flash ("Account is locked cannot log in Click here to unlock")
    #         # elif account['username'] != username:
    #         #     msg = ("Incorrect username!", "danger")
    #         # elif account['password'] != password:
    #         #     msg = ("Incorrect password!", "danger")
    #         # elif account is None:
    #         #     msg = "Username or Password is wrong"
    #         #     count+=1
    #         # cursor.execute('INSERT INTO accounts VALUES (NULL, %s,)',
    #         #                (count))
    #         # return render_template('index.html', msg=msg)
    #     else:
    #         msg = 'Enter Information'
    # except(TypeError):
    #     msg = "Incorrect username/password try again!"
    #     # Show the login form with message (if any)
    # return render_template('index.html', msg = msg)
    # Fetch one record and return result
    # if account and bcrypt.check_password_hash(user_hashpwd, password) and status:
    #     session['loggedin'] = True
    #     session['id'] = account['id']
    #     session['username'] = account['username']
    # # Redirect to home page
    # return redirect(url_for('home'))
    # else:
    #     # Account doesn’t exist or username/password incorrect
    #     msg = 'Incorrect username/password!'
    # # Show the login form with message (if any)
    # return render_template('index.html', msg='')
    # user_hashpwd = account['password']
    # status = account['status']
    # count = account['count']

    # if account and bcrypt.check_password_hash(user_hashpwd, password) and status:
    #     if status == 1:
    #         session['loggedin'] = True
    #         session['id'] = account['id']
    #         session['username'] = account['username']
    #
    #         # Redirect to home page
    #         return redirect(url_for('home'))
    #     elif status == 0:
    #         msg = "Account is locked cannot log in Click here to unlock"
    # elif account is None:
    #     msg = "Username or Password is wrong"
    #     count+=1

    # else:
    # #     # Account doesn’t exist or username/password incorrect
    #     msg = 'Incorrect username/password!'
    # # # Show the login form with message (if any)
    #     return render_template('index.html', msg=msg)


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
        captcha_response = request.form['g-recaptcha-response']
        status = request.form['status']
        if is_human(captcha_response):
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
                cursor.execute('INSERT INTO accounts VALUES (NULL, %s, %s, %s, %s, %s)',
                               (username, hashpwd, email, datetime, status,))
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
    session["google_email"] = id_info.get("google_email")
    return redirect("/MyWebApp/home")


# http://localhost:5000/MyWebApp/home - this will be the home page, only accessible for loggedin users
@app.route('/MyWebApp/home')
def home():
    # Check if user is loggedin
    if 'loggedin' in session:
        # User is loggedin show them the home page
        return render_template('home.html', username=session['username'])
    elif "google_id" in session:
        return render_template('google_home.html')
    # User is not loggedin redirect to login page
    return redirect(url_for('login'))


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


@app.route('/MyWebApp/createWarehouse', methods=['GET', 'POST'])
def create_warehouse():
    create_warehouse_form = CreateWarehouseForm(request.form)
    if request.method == 'POST' and create_warehouse_form.validate():
        warehouses_dict = {}
        db = shelve.open('warehouse.db', 'c')
        try:
            warehouses_dict = db['Warehouses']
            warehouse_list = []
            for key in warehouses_dict:
                warehouses = warehouses_dict.get(key)
                warehouse_list.append(warehouses)
            for warehouse in warehouse_list:
                Inventorys.Warehouse.count_id = warehouse.get_warehouse_id()
        except:
            print('Error in retrieving Warehouse from warehouse.db')

        if len(create_warehouse_form.supplier.data) == 0:
            create_warehouse_form.supplier.data = 'NIL'

        warehouse = Inventorys.Warehouse(
            product_number=create_warehouse_form.product_number.data,
            product=create_warehouse_form.product.data,
            quantity=create_warehouse_form.quantity.data,
            supplier=create_warehouse_form.supplier.data,
            threshold=create_warehouse_form.threshold.data,
            category=create_warehouse_form.category.data,
            sub_category=create_warehouse_form.sub_category.data, )
        warehouses_dict[warehouse.get_warehouse_id()] = warehouse
        db['Warehouses'] = warehouses_dict

        # Test codes
        warehouses_dict = db['Warehouses']
        warehouse = warehouses_dict[warehouse.get_warehouse_id()]
        print(warehouse.product, warehouse.category, warehouse.sub_category,
              "was stored in warehouse.db successfully with warehouse_id ==",
              warehouse.get_warehouse_id())

        db.close()

        return redirect(url_for('retrieve_warehouse'))
    return render_template('createWarehouse.html', form=create_warehouse_form)


@app.route('/MyWebApp/retrieve_Warehouse')
def retrieve_warehouse():
    warehouses_dict = {}
    db = shelve.open('warehouse.db', 'r')
    warehouses_dict = db['Warehouses']
    db.close()

    db = shelve.open('supplier.db', 'r')
    suppliers_dict: dict = db['Suppliers']
    db.close()

    db = shelve.open('order.db', 'r')
    orders_dict = db['Orders']
    db.close()

    warehouses_list = []
    for key in warehouses_dict:
        warehouse = warehouses_dict.get(key)
        warehouses_list.append(warehouse)

    suppliers_list = []
    for key in suppliers_dict:
        supplier = suppliers_dict.get(key)
        suppliers_list.append(supplier)

    orders_list = []
    for key in orders_dict:
        order = orders_dict.get(key)
        orders_list.append(order)

    return render_template('retrieveWarehouse.html', count=len(warehouses_list), warehouses_list=warehouses_list,
                           suppliers_list=suppliers_list, orders_list=orders_list)


@app.route('/MyWebApp/logout')
def logout():
    # Remove session data, this will log the user out
    session.pop('loggedin', None)
    session.pop('id', None)
    session.pop('username', None)
    session.clear()
    # Redirect to login page
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True)
