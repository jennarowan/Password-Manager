"""Authors: BitWizards(Kelvin Rodriguez, Shamar Barnes, Melissa Froh, Jeffrey Cauley, Jenna Rowan)
Project: CMSC 495 Capstone, Comprehensive Password Manager

Uses a flask environment to create a secure web application for generating and managing user's login
information for various applications. The user's can generate different passwords, and add, edit, delete, and
modify their passwords in the integrated SQLAlchemy database. The user will need to verify their account information
before accessing their information.

"""

import os
from os import path
from flask import Flask, render_template, redirect, url_for, request, flash
from flask_login import login_user, login_required
from flask_login import logout_user, current_user, LoginManager, UserMixin
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

osVar = os.name

if osVar == 'posix':
    dbName = "/home/ec2-user/CMSC-495-Project/instance/cmsc495.db"
elif osVar == 'nt':
    dbName = "cmsc495.db" #-- This is used when doing local testing.

bitwiz = Flask(__name__)
bitwiz.config['SECRET_KEY'] = 'WeAreVeryMagical1357913'
bitwiz.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{dbName}'
bitwiz.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Call the db
db = SQLAlchemy(bitwiz)

class user(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False)
    encryptedPassword = db.Column(db.String(200))
    salt = db.Column(db.String(50))
    passwordRecoveryQuestion = db.Column(db.String(300))
    passwordRecoveryAnswer = db.Column(db.String(100))

    def __init__(self, username, encryptedPassword, salt, passwordRecoveryQuestion, passwordRecoveryAnswer):
        self.username = username
        self.encryptedPassword = encryptedPassword
        self.salt = salt
        self.passwordRecoveryQuestion = passwordRecoveryQuestion
        self.passwordRecoveryAnswer = passwordRecoveryAnswer

class passwordEntry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    userId = db.Column(db.Integer)
    title = db.Column(db.String(100))
    encryptedPassword = db.Column(db.String(100))
    associatedUrl = db.Column(db.String(100))
    notes = db.Column(db.String(400))
    dateCreated = db.Column(db.Date)
    dateModified = db.Column(db.Time)

class passwordGenerator(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    algorithim = db.Column(db.String(100))
    length = db.Column(db.Integer)
    useUppercase = db.Column(db.Boolean)
    useLowercase = db.Column(db.Boolean)
    useNumbers = db.Column(db.Boolean)
    useSpeicalChars = db.Column(db.Boolean)

class encryptiionHandler(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    algorithmType = db.Column(db.String(100))
    encryptionKey = db.Column(db.String(100))

with bitwiz.app_context():
    if not path.exists(dbName):
        db.create_all()

def currentTime():
    """Returns the current time formatted to year, month, date and time."""
    dateTime = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    return dateTime

login_manager = LoginManager()
login_manager.login_view = 'login'

# User Loader for Login Manaager
@login_manager.user_loader
def load_user(id):
    return user.query.get(id)

@bitwiz.route('/register', methods=['POST', 'GET'])
def indexPage():
    """Renders the index page and handles new user registration."""
    username = None
    password = None
    salt = None
    question = None
    answer = None

    if request.method == 'POST':
        newUsername = request.form.get('username')
        newPassword = request.form.get('password')
        newSalt = request.form.get('salt')
        newQuestion = request.form.get('question')
        newAnswer = request.form.get('answer')

        newRec = user(newUsername, newPassword, newSalt, newQuestion, newAnswer)
        db.session.add(newRec)
        db.session.commit()
        login_user(newRec, remember=True)

        #TO DO -> FIGURE OUT WHAT PAGE SHOULD COME NEXT
        return redirect(url_for('nextPage'))

    return render_template('index.html', timestamp = currentTime(), title = 'CMST 495 - BitWizards')

@bitwiz.route('/PasswordGenerator', methods=['POST', 'GET'])
def passgeneration():
    """Renders the password generator page, and handles generating random passwords."""
    return render_template('PasswordGenerator.html')


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

        log_user = user.query.filter_by(username=username).first()

        # Check for existing user before logging in
        if log_user:
            if log_user.encryptedPassword == password:
                login_user(log_user, remember=True)
                return redirect(url_for('nextPage'))
            else:
                flash('Incorrect Password')
        else:
            flash('User Not Found')

        # Add the logic for Login

    return render_template('login.html', timestamp = currentTime(), title = 'CMST 495 - BitWizards')

@bitwiz.route('/PasswordEntry', methods=['GET', 'POST'])
def passentry():
    """Renders the password entry page, and handles the management of the user's passwords."""
    return render_template('PasswordEntry.html', timestamp = currentTime(), title = 'BitWizards - Password Entry')

@bitwiz.route('/PrivacyPolicy', methods=['GET', 'POST'])
def privacypage():
    """Renders the privacy page, which provides the user information about how information is stored securely."""
    return render_template('PrivacyPolicy.html', timestamp=currentTime(), title='BitWizards Privacy Page')

@bitwiz.route('/UserGuide', methods=['GET', 'POST'])
def userguide():
    """Renders the user guide page, which provides the user information about how to use the program."""
    return render_template('UserGuide.html', timestamp=currentTime(), title='BitWizards User Guide')

@bitwiz.route('/masterReset', methods=['POST', 'GET'])
def masterReset():
    """Renders the ResetMasterPass page, and handles authentication for resetting the master password."""
    if request.method == 'POST':

    # Get values entered in login
        formUser = request.form['username']

        checkUser = user.query.filter_by(username=formUser).first()      
    
        if checkUser:
            loggedUser = checkUser.username
            loggedQuestion = checkUser.passwordRecoveryQuestion
            return redirect(url_for('answerQuestion', sendUser=loggedUser, sendQuestion=loggedQuestion))
        else:
            flash('User Not Found. Please try again.')
    
    return render_template('ResetMasterPass.html', timestamp = currentTime(), title = 'Enter Username to Reset')

@bitwiz.route('/answer', methods=['POST', 'GET'])
def answerQuestion():
    """Renders the answer page, and handles updating the user's master password after verification."""
    if request.method == 'POST':

        formUser = request.form['sendUser']
        formAnswer = request.form['security_answer']
        formPass1 = request.form['firstPassword']
        formPass2 = request.form['secondPassword']

        updateUser = user.query.filter_by(username=formUser).first()

        if updateUser:
            if updateUser.passwordRecoveryAnswer == formAnswer:
                if formPass1 == formPass2:
                    updateUser.encryptedPassword = formPass1
                    db.session.commit()
                    return redirect(url_for('nextPage'))
                else:
                    flash('Passwords did not match. Try again.')
                    return redirect(url_for('masterReset'))
            else:
                flash('Incorrect Security Answer.')
                return redirect(url_for('masterReset'))
        else:
            flash('User does not exist')

    return render_template('answer.html', timestamp = currentTime(), title = 'Enter New Password')

@bitwiz.route('/next', methods=['GET'])
@login_required
def nextPage():
    """Renders the next page."""
    allRecords = user.query.all()

    flash('Hello There') #TESTLINE

    return render_template('next.html', records=allRecords, timestamp = currentTime(), title = 'Database Lookup')

login_manager.init_app(bitwiz)

if __name__ == '__main__':
    bitwiz.run(debug=True)  #TESTLINE
