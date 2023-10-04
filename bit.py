"""

Authors: BitWizards(Kelvin Rodriguez, Shamar Barnes, Melissa Froh, Jeffrey Cauley, Jenna Rowan)
Project: CMSC 495 Capstone, Comprehensive Password Manager

Uses a flask environment to create a secure web application for generating and managing user's login
information for various applications. The user's can generate different passwords, and add, edit, 
delete, and modify their passwords in the integrated SQLAlchemy database. The user will need to 
verify their account information before accessing their information.

"""

from os import path
import base64
import secrets
import string
from datetime import datetime, timezone
import bcrypt

from flask import Flask, render_template, redirect, url_for, request, flash, session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import login_user, login_required
from flask_login import logout_user, current_user, LoginManager, UserMixin
from flask_sqlalchemy import SQLAlchemy
from Crypto.Cipher import AES
from Crypto.Cipher import DES
from Crypto.Cipher import CAST
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

DB_NAME = "cmsc495.db"  # -- This is used when doing local testing.

bitwiz = Flask(__name__)
bitwiz.config['SECRET_KEY'] = 'WeAreVeryMagical1357913'
bitwiz.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DB_NAME}'
bitwiz.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Call the db
db = SQLAlchemy(bitwiz)

limiter = Limiter(
    get_remote_address,
    app=bitwiz,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)


class User(UserMixin, db.Model):
    """Creates the User table in the database."""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False)
    encrypted_password = db.Column(db.String(200), nullable=False)
    master_key = db.Column(db.String(200), nullable=False)
    password_recovery_question = db.Column(db.String(300))
    password_recovery_answer = db.Column(db.String(100))

    def __init__(self, username, encrypted_password, master_key, 
                 password_recovery_question, password_recovery_answer):
        self.username = username
        self.encrypted_password = bcrypt.hashpw(encrypted_password.encode(), bcrypt.gensalt())
        self.master_key = bcrypt.hashpw(master_key.encode(), bcrypt.gensalt())
        self.password_recovery_question = password_recovery_question
        self.password_recovery_answer = password_recovery_answer


class PasswordEntry(db.Model):
    """Creates the PasswordEntry table in the database."""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer)
    title = db.Column(db.String(100))
    app_user = db.Column(db.String(100))
    encrypted_password = db.Column(db.String(100))
    encryption_method = db.Column(db.String(100))
    associated_url = db.Column(db.String(100))
    notes = db.Column(db.String(400))
    date_created = db.Column(db.DateTime)
    date_modified = db.Column(db.DateTime)

    def __init__(self, user_id, title, app_user, password, encryption_method, associated_url,
                 notes, date_created, date_modified):
        self.user_id = user_id
        self.title = title
        self.app_user = app_user
        self.encrypted_password = password
        self.encryption_method = encryption_method
        self.associated_url = associated_url
        self.notes = notes
        self.date_created = date_created
        self.date_modified = date_modified


class EncryptionHandler(db.Model):
    """Creates the EncryptionHandler table in the database."""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer)
    key_one = db.Column(db.String(200), nullable=False)
    key_two = db.Column(db.String(200), nullable=False)

    def __init__(self, user_id, key_one, key_two):
        self.user_id = user_id
        self.key_one = key_one
        self.key_two = key_two


with bitwiz.app_context():
    if not path.exists(DB_NAME):
        db.create_all()


def generate_random_key():
    key_format = string.ascii_uppercase + string.ascii_lowercase + string.digits
    recovery_key = ''.join(secrets.choice(key_format) for i in range(8))
    return recovery_key

 
def generate_decryption_keys(user, password, key):
    unseen_key = generate_random_key()

    enc_password = encrypt_text(unseen_key, 'AES', password)
    enc_masterkey = encrypt_text(unseen_key, 'AES', key)

    new_key = EncryptionHandler(user, enc_password, enc_masterkey)
    db.session.add(new_key)
    db.session.commit() 

def update_master_pass_unseen_key(user_id, master_key):

    unseen_key = unlock_decrpytion('two', master_key)

    new_key = EncryptionHandler.query.filter_by(user_id=user_id).first()
    enc_password = encrypt_text(unseen_key, 'AES', GRAND_PASS)

    new_key.key_one = enc_password

        #update_pass = PasswordEntry.query.filter_by(id=mod_id).first()
        #update_pass.encrypted_password = encrypt_pass
    db.session.commit()


def unlock_decrpytion(selection, release_key):
#    o_keys = User.query.filter_by(
#        id=current_user.id).first()

    keys = EncryptionHandler.query.filter_by(
        user_id=current_user.id).first()

    if selection == 'one':
        padlock = keys.key_one

    elif selection == 'two':
        padlock = keys.key_two

    unlocked = aes_decrypt(padlock, release_key)
    return unlocked


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


def unpad(data):
    """Removes padding and returns data."""
    padding_length = data[-1]
    return data[:-padding_length]


def pad_des(data):
    """This function will pad the data to ensure it is a multiple of 8 bytes."""
    block_size = 8
    padding_length = block_size - (len(data) % block_size)
    padding = bytes([padding_length]) * padding_length
    return data + padding


def encrypt_text(text_to_encrypt, algorithm_choice, unlock_key):
    """This function will encrypt the provided string with the chosen algorithm."""
    print('WHAT IS UNLOCK KEY: =============================')
    print(unlock_key)

    # the users message will be encrypted with the chosen algorithm
    if algorithm_choice == "AES":
        # AES encryption
        # Pad the message to ensure it is a multiple of 16 bytes
        padded_message = pad(text_to_encrypt.encode())
        # Pad the key
        padded_key = pad(str.encode(unlock_key))
        # create a new AES object
        aes_object = AES.new(padded_key, AES.MODE_ECB)
        # encrypt the message
        encrypted_message = aes_object.encrypt(padded_message)
        ciphertext = base64.b64encode(encrypted_message)
        return ciphertext

    elif algorithm_choice == "DES":
        # DES encryption
        # Pad the message to ensure it is a multiple of 8 bytes
        #padded_message = pad_des(text_to_encrypt.encode())
        padded_message = pad_des(str.encode(text_to_encrypt))
        # Pad the key
        #padded_key = pad_des(str.encode(unlock_key))
        padded_key = str.encode(unlock_key)
        # create a new DES object
        des_object = DES.new(padded_key, DES.MODE_ECB)
        # encrypt the message
        encrypted_message = des_object.encrypt(padded_message)
        ciphertext = base64.b64encode(encrypted_message)
        return ciphertext

    elif algorithm_choice == "Blowfish":
        # Blowfish encryption
        iv = b'12345678'  # Initialization Vector (IV) - Change as needed
        # Pad the key
        padded_key = str.encode(unlock_key)
        # Create a Blowfish cipher object
        cipher = Cipher(algorithms.Blowfish(padded_key), modes.CFB(iv))
        encryptor = cipher.encryptor()
        # Pad the message using PKCS7 padding
        padder = padding.PKCS7(64).padder()
        padded_message = padder.update(
            text_to_encrypt.encode()) + padder.finalize()
        # Encrypt the padded message
        encrypted_message = encryptor.update(
            padded_message) + encryptor.finalize()
        ciphertext = base64.b64encode(encrypted_message)

        return ciphertext

    elif algorithm_choice == "CAST5":
        # CAST5 encryption
        # Pad the message to ensure it is a multiple of 8 bytes
        padded_message = pad_des(text_to_encrypt.encode())
        # Pad the key
        padded_key = pad_des(str.encode(unlock_key))
        # create a new CAST5 object
        cast5_object = CAST.new(padded_key, CAST.MODE_ECB)
        # encrypt the message
        encrypted_message = cast5_object.encrypt(padded_message)
        ciphertext = base64.b64encode(encrypted_message)

        return ciphertext
    

"""
def aes_decrypt(ciphertext, pass_key):
    try:
        padded_key = pad(str.encode(pass_key))
        print('PADDED KEY: ')
        print(padded_key)
        aes_object = AES.new(padded_key, AES.MODE_ECB)
        decoded = base64.b64decode(ciphertext)
        print('DECODED: ')
        print(decoded)
        decrypted_bytes = aes_object.decrypt(decoded)
        print('BYTES: ')
        print(decrypted_bytes)
        decrypted_value = unpad(decrypted_bytes).decode()
        print('VALUE: ')
        print(decrypted_value)
        return decrypted_value
    except:
        return 'Error'
"""

def aes_decrypt(ciphertext, pass_key):
    """Decrypts and returns plain-text versions of AES."""
    try:
        padded_key = pad(str.encode(pass_key))
        aes_object = AES.new(padded_key, AES.MODE_ECB)
        decoded = base64.b64decode(ciphertext)
        decrypted_bytes = aes_object.decrypt(decoded)
        decrypted_value = unpad(decrypted_bytes).decode()
        return decrypted_value
    except:
        return 'Error'


def des_decrypt(ciphertext, pass_key):
    """Decrypts and returns plain-text versions of DES."""
    try:
        #padded_key = pad_des(str.encode(pass_key))
        padded_key = str.encode(pass_key)
        des_object = DES.new(padded_key, DES.MODE_ECB)
        decrypted_bytes = des_object.decrypt(
            base64.b64decode(ciphertext))
        decrypted_value = unpad(decrypted_bytes).decode('utf-8')
        return decrypted_value
    except:
        return 'Error'


def cast5_decrypt(ciphertext, pass_key):
    """Decrypts and returns plain-text versions of CAST5."""
    try:
        padded_key = pad_des(str.encode(pass_key))
        cast5_object = CAST.new(padded_key, CAST.MODE_ECB)
        decrypted_bytes = cast5_object.decrypt(
            base64.b64decode(ciphertext))
        decrypted_value = unpad(decrypted_bytes).decode('utf-8')
        return decrypted_value
    except:
        return 'Error'


def blowfish_decrypt(ciphertext, pass_key):
    """Decrypts and returns plain-text versions of Blowfish."""
    try:
        iv = b'12345678'
        #padded_key = pad_des(str.encode(pass_key))
        padded_key = str.encode(pass_key)
        blowfish_object = Cipher(algorithms.Blowfish(padded_key), modes.CFB(iv))
        decryptor = blowfish_object.decryptor()
        encrypted_type = base64.b64decode(ciphertext)
        decrypted_type = decryptor.update(
            encrypted_type) + decryptor.finalize()
        unpad = padding.PKCS7(64).unpadder()
        original_type = unpad.update(
            decrypted_type) + unpad.finalize()
        decrypted_value = original_type.decode('UTF-8')
        return decrypted_value
    except:
        return 'Error'


def decrypt_password(ciphertext, algorithm_choice, choice, release_key):
    """This function will decrypt the encrypted password with the chosen algorithm."""

    print('===UNLOCK DETAILS===')
    print(choice)
    print(release_key)

    pass_key = unlock_decrpytion(choice, release_key)
    print('====PASS KEY====')
    print(pass_key)

    if algorithm_choice == 'AES':
        password = aes_decrypt(ciphertext, pass_key)
    elif algorithm_choice == 'DES':
        password = des_decrypt(ciphertext, pass_key)
    elif algorithm_choice == 'CAST5':
        password = cast5_decrypt(ciphertext, pass_key)
    elif algorithm_choice == 'Blowfish':
        password = blowfish_decrypt(ciphertext, pass_key)

    return password


def decrypt_algorithm_choice(encrypted_algorithm_choice, choice, release_key):
    """
    This function will decrypt the encrypted algorithm choice
    that was used with the stored password.

    It will do so by trying each decryption method until the
    correct one is found.
    """
    print('RELEASE KEY: ')
    print(release_key)

    pass_key = unlock_decrpytion(choice, release_key)
    print('DECRYPTED PASS KEY: ')
    print(pass_key)

    # Check for AES decryption
    if aes_decrypt(encrypted_algorithm_choice, pass_key) == 'AES':
        return 'AES'
    # Check for DES decryption
    if des_decrypt(encrypted_algorithm_choice, pass_key) == 'DES':
        return 'DES'
    # Check for CAST5 decryption
    if cast5_decrypt(encrypted_algorithm_choice, pass_key) == 'CAST5':
        return 'CAST5'
    # Check for Blowfish decryption
    if blowfish_decrypt(encrypted_algorithm_choice, pass_key) == 'Blowfish':
        return 'Blowfish'


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
        securepassword: A password formed using the secrets module to the specifications.

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


#def reencrypt_passwords(user_id, password_new, redo_key):
  #  """Re-encrypts all passwords in the database with the new master password."""

    # Pull necessary database records
 #   password_entries = PasswordEntry.query.filter_by(user_id=user_id).all()
 #   unseen_record = EncryptionHandler.query.filter_by(user_id=user_id).first()

    # Unlock the unseen key using the master key
 #   unseen_key = aes_decrypt(unseen_record.key_two, redo_key)

    # Decrypt all passwords with the unseen key
#    for entry in password_entries:
#        plain_algo = decrypt_algorithm_choice(entry.encryption_method, 'two', redo_key)
#        print('PLAIN ALGORITHM: ')
#        print(plain_algo)
#        plain_pass = decrypt_password(entry.encrypted_password, plain_algo, 'two', redo_key)
#       new_enc_pass = encrypt_text(plain_pass, plain_algo, unseen_key)
#        new_enc_algo = encrypt_text(plain_algo, plain_algo, unseen_key)

#        entry.encrypted_password = new_enc_pass
#        entry.encrypted_method = new_enc_algo
#        db.session.commit()


def update_password(password):
    """Updates the global password key variables with the provided password."""

    global GRAND_PASS 
    GRAND_PASS = password

    #PASSWORD_KEY_AES = pad(str.encode(password))
    #PASSWORD_KEY_DES = pad_des(str.encode(password))
    #PASSWORD_KEY_BLOWFISH = str.encode(password)
    #PASSWORD_KEY_CAST5 = pad_des(str.encode(password))

login_manager = LoginManager()
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    """Returns the user's id."""
    return db.session.get(User, user_id)

@bitwiz.route('/register', methods=['POST', 'GET'])
def register_page():
    """Renders the index page and handles new user registration."""

    if request.method == 'POST':
        new_username = request.form.get('username')
        new_password = request.form.get('password')
        new_question = request.form.get('question')
        new_answer = request.form.get('answer')

        new_master_key = generate_random_key()
        update_password(new_password)

        new_rec = User(new_username, new_password, new_master_key, new_question, new_answer)
        db.session.add(new_rec)
        db.session.commit()
        login_user(new_rec, remember=True)

        # Generate decryptor keys 
        # Save decryptor keys to the db
        generate_decryption_keys(current_user.id, new_password, new_master_key)

        return redirect(url_for('success_page', user=new_username, key=new_master_key))
    
    return render_template('register.html', timestamp=current_time(), title='CMST 495 - BitWizards')


@bitwiz.route('/success')
def success_page():
    success_user = request.args.get('user')
    success_key = request.args.get('key')

    return render_template('success.html', timestamp=current_time(), user=success_user, 
                           key=success_key, title='CMST 495 - BitWizards')


@bitwiz.route('/', methods=['GET', 'POST'])
@bitwiz.route('/index', methods=['GET', 'POST'])
@limiter.limit('3/second', override_defaults=False)
def login():
    """Renders the login page, and handles the user authentication."""
    if request.method == 'POST':
        # Get values entered in login

        username = request.form['username']
        password = request.form['password']

        log_user = User.query.filter_by(username=username).first()

        update_password(password)

        # Check for existing user before logging in
        if log_user:
            if bcrypt.checkpw(password.encode(), log_user.encrypted_password):
                session.pop('last_activity', None)
                login_user(log_user, remember=True)
                return redirect(url_for('userguide'))
            flash('Incorrect Password')
        else:
            flash('User Not Found')

        # Add the logic for Login

    return render_template('index.html', timestamp=current_time(), title='CMST 495 - BitWizards')


@bitwiz.route('/PasswordGenerator', methods=['POST', 'GET'])
def passgeneration():
    """Renders the password generator page, and generates and populates random passwords."""
    logged_in = current_user.is_authenticated
    temppassword = ""
    if request.method == 'POST':
        # Get values from checkbox and slider on password generator page
        uppercase = request.form.get('uppercase')
        lowercase = request.form.get('lowercase')
        numbers = request.form.get('numbers')
        symbols = request.form.get('symbols')
        length = int(request.form.get('length'))

        if uppercase is None and lowercase is None and numbers is None and symbols is None:
            flash('Please select at least one option before generating a password.')

        else:
            temppassword = generate_password(
                uppercase, lowercase, numbers, symbols, length)

    return render_template('PasswordGenerator.html',
                           passwordOutput=temppassword, timestamp=current_time(),
                           title='CMST 495 - BitWizards', logged_in=logged_in)


@bitwiz.route('/slider_update', methods=['POST', 'GET'])
def slider():
    """Handles the password generator slider value updating on new input from user."""
    received_data = request.data
    return received_data


@bitwiz.route('/pass_entry', methods=['GET', 'POST'])
@login_required
def pass_entry():
    """Renders the password entry page, and handles the management of the user's passwords."""
    if 'password' in request.args:
        passed_password = request.args.get('password')
    else:
        passed_password = None

    if request.method == 'POST':
        app_desc_name = request.form['application']
        app_user = request.form['username']
        app_password = request.form['password']
        app_algorithm = request.form['algorithm']
        app_url = request.form['given_url']
        app_notes = request.form['notes']

        curruser_id = current_user.id

        unseen_key = unlock_decrpytion('one', GRAND_PASS)

        # Encrypt password and algorithm
        encrypt_pass = encrypt_text(app_password, app_algorithm, unseen_key)
        encrypt_algo = encrypt_text(app_algorithm, app_algorithm, unseen_key)

        new_pass = PasswordEntry(curruser_id, app_desc_name, app_user,
                                 encrypt_pass, encrypt_algo, app_url,
                                 app_notes, datetime.now(), datetime.now())
        db.session.add(new_pass)
        db.session.commit()

        return redirect(url_for('next_page', user_val=curruser_id))

    return render_template('PasswordEntry.html', timestamp=current_time(),
                           title='CMST 495 - BitWizards - Create Password', passed=passed_password)


@bitwiz.route('/PrivacyPolicy', methods=['GET', 'POST'])
def privacypage():
    """Renders the privacy page, which provides the user information security features."""
    return render_template('PrivacyPolicy.html',
                           timestamp=current_time(), title='BitWizards Privacy Page')


@bitwiz.route('/UserGuide', methods=['GET', 'POST'])
def userguide():
    """Renders the user guide page, which provides instructions and FAQ answers."""
    return render_template('UserGuide.html',
                           timestamp=current_time(), title='BitWizards User Guide')


@bitwiz.route('/master_reset', methods=['POST', 'GET'])
def master_reset():
    """Renders the ResetMasterPass page, and allows resetting the master password."""
    if request.method == 'POST':

        # Get values entered in login
        form_user = request.form['username']

        check_user = User.query.filter_by(username=form_user).first()

        if check_user:
            logged_user = check_user.username
            logged_question = check_user.password_recovery_question

            return redirect(url_for('answer_question',
                                    sendUser=logged_user, sendQuestion=logged_question))

        flash('User Not Found. Please try again.')

    return render_template('reset.html', timestamp=current_time(), title='Enter Username to Reset')


@bitwiz.route('/answer', methods=['POST', 'GET'])
def answer_question():
    """Renders the answer page, and updates the user's master password after verification."""
    if request.method == 'POST':

        form_user = request.form['sendUser']
        form_answer = request.form['security_answer']
        form_pass_1 = request.form['firstPassword']
        form_pass_2 = request.form['secondPassword']
        form_master = request.form['master_key']

        update_user = User.query.filter_by(username=form_user).first()

        if update_user:
            if bcrypt.checkpw(form_master.encode(), update_user.master_key):
                if update_user.password_recovery_answer == form_answer:
                    if form_pass_1 == form_pass_2:
                        update_user.encrypted_password = bcrypt.hashpw(form_pass_1.encode(),
                                                                   bcrypt.gensalt())
                        db.session.commit()

                        session.pop('last_activity', None)
                        login_user(update_user, remember=True)

                        update_password(form_pass_1)

                        update_master_pass_unseen_key(current_user.id, form_master)

                        # Decrypt all passwords and re-encrypt them with the new master password
 #                       reencrypt_passwords(update_user.id, form_pass_1, form_master)

                        return redirect(url_for('next_page'))
                    else:
                        flash('Passwords did not match. Try again.')
                        return redirect(url_for('master_reset'))
                else:
                    flash('Incorrect Security Answer.')
                    return redirect(url_for('master_reset'))
            else:
                flash('Master Key does not match')
        else:
            flash('User does not exist')

    return render_template('answer.html', timestamp=current_time(), title='Enter New Password')


@bitwiz.route('/next', methods=['GET', 'POST'])
@login_required
def next_page():
    """Renders the next page, and shows decrypted password information."""

    user_record = User.query.filter_by(id=current_user.id).all()
    password_records = PasswordEntry.query.filter_by(
        user_id=current_user.id).all()

    plain_text = ""
    plain_algo = ""

    for record in password_records:
        password = record.encrypted_password
        encryption_method = record.encryption_method

        print('==========GRAND PASS===========')
        print(GRAND_PASS)
        print('==========ENC METHOD===========')
        print(encryption_method)        

        plain_algo = decrypt_algorithm_choice(encryption_method, 'one', GRAND_PASS)
        print('==========PLAIN ALGO===========')
        print(plain_algo)
        plain_text = decrypt_password(password, plain_algo, 'one', GRAND_PASS)

        record.plain_text = plain_text
        record.plain_algo = plain_algo

    return render_template('next.html', user_record=user_record,
                           password_records=password_records, plain_text=plain_text,
                           plain_algo=plain_algo, timestamp=current_time(), title='Database Lookup')


@bitwiz.route('/ModifyPassword', methods=['GET', 'POST'])
@login_required
def modify_password():
    """Renders the modify password page, and receives stored data the user selected to modify."""
    if request.method == 'GET':
        og_title = request.args.get('title')
        og_user = request.args.get('username')
        og_pass = request.args.get('password')
        og_id = request.args.get('record_id')
        og_algo = request.args.get('algorithm')

    if request.method == 'POST':

        mod_id = int(request.form.get('record_id'))
        # mod_title = request.form.get('title')
        mod_user = request.form.get('username')
        mod_pass = request.form.get('password')
        mod_algo = request.form.get('algorithm')
        mod_url = request.form.get('url')
        mod_notes = request.form.get('notes')

        if 'modify' in request.form:
            unseen_key = unlock_decrpytion('one', GRAND_PASS)
            encrypt_pass = encrypt_text(mod_pass, mod_algo, unseen_key)
            update_pass = PasswordEntry.query.filter_by(id=mod_id).first()
            encrypt_algo = encrypt_text(mod_algo, mod_algo, unseen_key)

            if update_pass:
                # update_pass.title = mod_title
                update_pass.app_user = mod_user
                update_pass.encrypted_password = encrypt_pass
                update_pass.associated_url = mod_url
                update_pass.notes = mod_notes
                update_pass.date_modified = datetime.now()
                update_pass.encryption_method = encrypt_algo

                db.session.commit()
                flash('Password entry modified successfully.')

        elif 'delete' in request.form:
            # Handle deletion logic here
            password_entry = PasswordEntry.query.get(mod_id)

            if password_entry:
                # Check if the password entry belongs to the currently logged-in user
                if password_entry.user_id == current_user.id:
                    # Delete the password entry from the database
                    db.session.delete(password_entry)
                    db.session.commit()
                    flash('Password entry deleted successfully.')
                else:
                    flash('Unauthorized to delete this password entry.')
            else:
                flash('Password entry not found.')

        return redirect(url_for('next_page'))

    return render_template('ModifyPassword.html', application=og_title,
                           username=og_user, record_id=og_id, password=og_pass,
                           algorithm=og_algo, timestamp=current_time(), title='Modify Entry')


@login_required
@bitwiz.before_request
def before_request():
    """Checks user's last activity, and logs out after inactivity."""
    if current_user.is_authenticated:
        session.permanent = True
        last_activity_time = session.get('last_activity')
        if 'last_activity' in session:
            curr_time = datetime.now(timezone.utc)
            time_diff = curr_time - last_activity_time
            if time_diff.total_seconds() > 600:
                logout_user()
                flash('Your session has expired. You have been logged out.')
                return redirect(url_for('login'))
        else:
            session['last_activity'] = datetime.now(timezone.utc)
        session['last_activity'] = datetime.now(timezone.utc)


@bitwiz.route('/logout')
@login_required
def logout():
    """Calls function to log out, and redirects to the login page after logout."""
    session.pop('last_activity', None)
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('login'))


login_manager.init_app(bitwiz)

if __name__ == '__main__':
    bitwiz.run(debug=True)  # TESTLINE