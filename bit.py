"""

Authors: BitWizards(Kelvin Rodriguez, Shamar Barnes, Melissa Froh, Jeffrey Cauley, Jenna Rowan)
Project: CMSC 495 Capstone, Comprehensive Password Manager

Uses a flask environment to create a secure web application for generating and managing user's login
information for various applications. The user's can generate different passwords, and add, edit, 
delete, and modify their passwords in the integrated SQLAlchemy database. The user will need to 
verify their account information before accessing their information.

"""

#import os
from os import path
import base64
import secrets
import string
from datetime import datetime
import requests

from flask import Flask, render_template, redirect, url_for, request, flash
from flask_login import login_user, login_required
from flask_login import logout_user, current_user, LoginManager, UserMixin
from flask_sqlalchemy import SQLAlchemy
from Crypto.Cipher import AES
from Crypto.Cipher import DES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

#osVar = os.name

# Gathered at login, used as encryption key
PASSWORD_KEY_AES = None
PASSWORD_KEY_DES = None

def is_aws():
    """Checks if the application is running on an AWS EC2 instance."""
    try:
        response = requests.get('http://169.254.169.254/latest/meta-data/instance-id', timeout=1)
        return True if response.status_code == 200 else False
    except requests.RequestException:
        return False

if is_aws():
    DB_NAME = "/home/ec2-user/CMSC-495-Project/instance/cmsc495.db"
else:
    DB_NAME = "cmsc495.db" #-- This is used when doing local testing.

#if osVar == 'posix':
#    DB_NAME = "/home/ec2-user/CMSC-495-Project/instance/cmsc495.db"
#elif osVar == 'nt':
#    DB_NAME = "cmsc495.db" #-- This is used when doing local testing.

bitwiz = Flask(__name__)
bitwiz.config['SECRET_KEY'] = 'WeAreVeryMagical1357913'
bitwiz.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DB_NAME}'
bitwiz.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Call the db
db = SQLAlchemy(bitwiz)

class User(UserMixin, db.Model):
    """Creates the User table in the database."""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False)
    encrypted_password = db.Column(db.String(200))
    salt = db.Column(db.String(50))
    password_recovery_question = db.Column(db.String(300))
    password_recovery_answer = db.Column(db.String(100))

    def __init__(self, username, encrypted_password, salt, password_recovery_question, 
                 password_recovery_answer):
        self.username = username
        self.encrypted_password = encrypted_password
        self.salt = salt
        self.password_recovery_question = password_recovery_question
        self.password_recovery_answer = password_recovery_answer

class PasswordEntry(db.Model):
    """Creates the PasswordEntry table in the database."""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer)
    title = db.Column(db.String(100))
    app_user = db.Column(db.String(100))
    encrypted_password = db.Column(db.String(100))
    associated_url = db.Column(db.String(100))
    notes = db.Column(db.String(400))
    date_created = db.Column(db.DateTime)
    date_modified = db.Column(db.DateTime)

    def __init__(self, user_id, title, app_user, encrypted_password, associated_url, notes, date_created, date_modified):
        self.user_id = user_id
        self.title = title
        self.app_user = app_user
        self.encrypted_password = encrypted_password
        self.associated_url = associated_url
        self.notes = notes
        self.date_created = date_created
        self.date_modified = date_modified

class PasswordGenerator(db.Model):
    """Creates the PasswordGenerator table in the database."""
    id = db.Column(db.Integer, primary_key=True)
    algorithim = db.Column(db.String(100))
    length = db.Column(db.Integer)
    useUppercase = db.Column(db.Boolean)
    useLowercase = db.Column(db.Boolean)
    useNumbers = db.Column(db.Boolean)
    useSpeicalChars = db.Column(db.Boolean)

class EncryptionHandler(db.Model):
    """Creates the EncryptionHandler table in the database."""
    id = db.Column(db.Integer, primary_key=True)
    algorithmType = db.Column(db.String(100))
    encryptionKey = db.Column(db.String(100))

with bitwiz.app_context():
    if not path.exists(DB_NAME):
        db.create_all()

def current_time():
    """Returns the current time formatted to year, month, date and time."""
    date_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    return date_time

def pad(data):
    """This function will pad the data to ensure it is a multiple of 16 bytes."""
    block_size = 16
    padding_length = block_size - (len(data) % block_size)
    padding = bytes([padding_length]) * padding_length
    return data + padding

def pad_des(data):
    """This function will pad the data to ensure it is a multiple of 8 bytes."""
    block_size = 8
    padding_length = block_size - (len(data) % block_size)
    padding = bytes([padding_length]) * padding_length
    return data + padding

def encrypt_password(password, algorithm_choice):
    """This function will encrypt the user's password with the chosen algorithm."""

    # the users message will be encrypted with the chosen algorithm
    if algorithm_choice == "AES":
        # AES encryption
        # Pad the message to ensure it is a multiple of 16 bytes
        padded_message = pad(password.encode())
        # create a new AES object
        aes_object = AES.new(PASSWORD_KEY_AES, AES.MODE_ECB)
        # encrypt the message
        encrypted_message = aes_object.encrypt(padded_message)
        ciphertext = base64.b64encode(encrypted_message)
        # print the encrypted message
        return ciphertext
    
    elif algorithm_choice == "DES":
        # DES encryption
        # Pad the message to ensure it is a multiple of 8 bytes
        padded_message = pad(password.encode())
        # create a new DES object
        des_object = DES.new(PASSWORD_KEY_DES, DES.MODE_ECB)
        # encrypt the message
        encrypted_message = des_object.encrypt(padded_message)
        ciphertext = base64.b64encode(encrypted_message)
        # print the encrypted message
        #   print("Your message encrypted with DES is: ")
        #   print(ciphertext)
        return ciphertext
    
    elif algorithm_choice == "RSA":
        # RSA encryption
        # Generate a random key pair for RSA (public and private keys)
        rsa_key = RSA.generate(2048)
        # Extract the public key for encryption
        rsa_public_key = rsa_key.publickey()
        # Use PKCS1_OAEP padding
        cipher_rsa = PKCS1_OAEP.new(rsa_public_key)
        # Pad the message to ensure it can be encrypted properly
        padded_message = pad(password.encode())
        # Encrypt the message using RSA with OAEP padding
        encrypted_message = cipher_rsa.encrypt(padded_message)
        ciphertext = base64.b64encode(encrypted_message)
        # Print the encrypted message
        #    print("Your message encrypted with RSA is: ")
        #    print(ciphertext)
        return ciphertext

login_manager = LoginManager()
login_manager.login_view = 'login'

# User Loader for Login Manaager
@login_manager.user_loader
def load_user(user_id):
    """Returns the user's id."""
    return User.query.get(user_id)

@bitwiz.route('/register', methods=['POST', 'GET'])
def index_page():
    """Renders the index page and handles new user registration."""
    # username = None
    # password = None
    # salt = None
    # question = None
    # answer = None

    if request.method == 'POST':
        new_username = request.form.get('username')
        new_password = request.form.get('password')
        new_salt = request.form.get('salt')
        new_question = request.form.get('question')
        new_answer = request.form.get('answer')

        new_rec = User(new_username, new_password, new_salt, new_question, new_answer)
        db.session.add(new_rec)
        db.session.commit()
        login_user(new_rec, remember=True)

        #TO DO -> FIGURE OUT WHAT PAGE SHOULD COME NEXT
        return redirect(url_for('next_page'))

    return render_template('index.html', timestamp = current_time(), title = 'CMST 495 - BitWizards')

@bitwiz.route('/PasswordGenerator', methods=['POST', 'GET'])
def passgeneration():
    """Renders the password generator page, and handles generating and populating random passwords."""
    temppassword = ""
    if request.method == 'POST':
        # Get values from checkbox and slider on password generator page
        uppercase = request.form.get('uppercase')
        lowercase = request.form.get('lowercase')
        numbers = request.form.get('numbers')
        symbols = request.form.get('symbols')
        length = int(request.form.get('length'))
        temppassword = generate_password(uppercase, lowercase, numbers, symbols, length)

    return render_template('PasswordGenerator.html', passwordOutput=temppassword,
                           timestamp=current_time(), title='CMST 495 - BitWizards')


def generate_password(uppercase, lowercase, numbers, symbols, length):
    """ Join characters to form random secure password using user specified characters,
    returns the password.

    Args:
        uppercase: Flag for if uppercase is included in the set of characters
        lowercase: Flag for if lowercase is included in the set of characters
        numbers: Flag for if digits are included in the set of characters
        symbols: Flag for if symbols are included in the set of characters
        length: The lenght of the password to be generated
    Returns:
        securepassword: A password formed using the secrets module to the specified length ans ascii set.

    """
    alphabet = ""
    if uppercase:
        alphabet += string.ascii_uppercase

    if lowercase:
        alphabet += string.ascii_lowercase

    if numbers:
        alphabet += string.digits

    if symbols:
        alphabet += string.punctuation

    securepassword = ''.join(secrets.choice(alphabet) for i in range(length))
    return securepassword


@bitwiz.route('/slider_update', methods=['POST', 'GET'])
def slider():
    """Handles the password generator slider value updating on new input from user."""
    received_data = request.data
    return received_data


@bitwiz.route('/', methods=['GET', 'POST'])
def login():
    """Renders the login page, and handles the user authentication."""
    if request.method == 'POST':
        # Get values entered in login

        username = request.form['username']
        password = request.form['password']

        global PASSWORD_KEY_AES
        global PASSWORD_KEY_DES
        PASSWORD_KEY_AES = pad(str.encode(request.form['password']))
        PASSWORD_KEY_DES = pad_des(str.encode(request.form['password']))

        log_user = User.query.filter_by(username=username).first()

        # Check for existing user before logging in
        if log_user:
            if log_user.encrypted_password == password:
                login_user(log_user, remember=True)
                return redirect(url_for('next_page'))
            else:
                flash('Incorrect Password')
        else:
            flash('User Not Found')

        # Add the logic for Login

    return render_template('login.html', timestamp = current_time(), title = 'CMST 495 - BitWizards')

@bitwiz.route('/PasswordEntry', methods=['GET', 'POST'])
@login_required
def pass_entry():
    """Renders the password entry page, and handles the management of the user's passwords."""
    if request.method == 'POST':
        app_desc_name = request.form['application']
        app_user = request.form['username']
        app_password = request.form['password']
        app_algorithm = request.form['algorithm']

        curruser_id = current_user.id

        enc_pass = encrypt_password(app_password, app_algorithm)

        new_pass = PasswordEntry(curruser_id, app_desc_name, app_user, enc_pass, None, None, datetime.now(), datetime.now())
        db.session.add(new_pass)
        db.session.commit()

        return redirect(url_for('query_page', user_val = curruser_id))
    
    return render_template('PasswordEntry.html', timestamp = current_time(), title = 'CMST 495 - BitWizards - Create Password')

@bitwiz.route('/PrivacyPolicy', methods=['GET', 'POST'])
def privacypage():
    """Renders the privacy page, which provides the user information about how information is stored securely."""
    return render_template('PrivacyPolicy.html', timestamp=current_time(), title='BitWizards Privacy Page')

@bitwiz.route('/UserGuide', methods=['GET', 'POST'])
def userguide():
    """
    Renders the user guide page, which provides the user information about how to use the program.
    """
    return render_template('UserGuide.html', timestamp=current_time(), title='BitWizards User Guide')

@bitwiz.route('/master_reset', methods=['POST', 'GET'])
def master_reset():
    """Renders the ResetMasterPass page, and handles authentication for resetting the master password."""
    if request.method == 'POST':

    # Get values entered in login
        form_user = request.form['username']

        check_user = User.query.filter_by(username=form_user).first()      
    
        if check_user:
            logged_user = check_user.username
            logged_question = check_user.password_recovery_question
            return redirect(url_for('answer_question', sendUser=logged_user, sendQuestion=logged_question))
        else:
            flash('User Not Found. Please try again.')
    
    return render_template('ResetMasterPass.html', timestamp = current_time(), title = 'Enter Username to Reset')

@bitwiz.route('/answer', methods=['POST', 'GET'])
def answer_question():
    """Renders the answer page, and handles updating the user's master password after verification."""
    if request.method == 'POST':

        form_user = request.form['sendUser']
        form_answer = request.form['security_answer']
        form_pass_1 = request.form['firstPassword']
        form_pass_2 = request.form['secondPassword']

        update_user = User.query.filter_by(username=form_user).first()

        if update_user:
            if update_user.password_recovery_answer == form_answer:
                if form_pass_1 == form_pass_2:
                    update_user.encrypted_password = form_pass_1
                    db.session.commit()
                    return redirect(url_for('next_page'))
                else:
                    flash('Passwords did not match. Try again.')
                    return redirect(url_for('master_reset'))
            else:
                flash('Incorrect Security Answer.')
                return redirect(url_for('master_reset'))
        else:
            flash('User does not exist')

    return render_template('answer.html', timestamp = current_time(), title = 'Enter New Password')

@bitwiz.route('/next', methods=['GET', 'POST'])
@login_required
def next_page():
    """Renders the next page."""
    user_record = User.query.filter_by(id=current_user.id).all()
    password_records = PasswordEntry.query.filter_by(user_id=current_user.id).all()
    print(user_record)
    print(password_records)
    flash('Hello There') #TESTLINE

    return render_template('next.html', user_record=user_record,
                           password_records=password_records, timestamp=current_time(), title='Database Lookup')


@bitwiz.route('/ModifyPassword', methods=['GET', 'POST'])
@login_required
def modify_password():
    """Renders the modify password page, and receives stored data the user selected to modify."""
    title = request.args.get('title')
    username = request.args.get('username')
    password = request.args.get('password')

    if request.method == 'POST':
        # Add logic to write new user data to database
        return redirect(url_for('next_page'))

    return render_template('ModifyPassword.html', application=title, username=username,
                           password=password, timestamp=current_time(), title='Modify Entry')

@bitwiz.route('/logout')
@login_required
def logout():
    """Calls helper function to log out, and redirects to the login page after session is terminated."""
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('login'))

@bitwiz.route('/query/<int:user_val>', methods=['GET'])
@login_required
def query_page(user_val):
    """Renders the queries page."""
    all_records = PasswordEntry.query.filter_by(user_id=user_val)

    flash('Hello There') #TESTLINE

    return render_template('query.html', records=all_records, timestamp = current_time(), title = 'Database Query Tester')
    
login_manager.init_app(bitwiz)

if __name__ == '__main__':
    bitwiz.run(debug=True)  #TESTLINE
