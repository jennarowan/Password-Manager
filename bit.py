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
    dbName = "instance/cmsc495.db" #-- This is used when doing local testing.

bitwiz = Flask(__name__)
bitwiz.config['SECRET_KEY'] = 'WeAreVeryMagical1357913'
bitwiz.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{dbName}'
bitwiz.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Call the db
db = SQLAlchemy(bitwiz)

def create_db(app):
    ''' Function that builds the database'''
    if not path.exists(dbName):
        db.create_all(app=bitwiz)

def currentTime():
    dateTime = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    return dateTime

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

login_manager = LoginManager()
login_manager.login_view = 'login'

# User Loader for Login Manaager
@login_manager.user_loader
def load_user(id):
    return user.query.get(id)

@bitwiz.route('/register', methods=['POST', 'GET'])
def indexPage():
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
    return render_template('PasswordGenerator.html')


@bitwiz.route('/slider_update', methods=['POST', 'GET'])
def slider():
    received_data = request.data
    return received_data


@bitwiz.route('/', methods=['GET', 'POST'])
def login():
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
    return render_template('PasswordEntry.html', timestamp = currentTime(), title = 'CMST 495 - BitWizards')

@bitwiz.route('/masterReset', methods=['POST', 'GET'])
def masterReset():
    return render_template('ResetMasterPass.html')

@bitwiz.route('/next', methods=['GET'])
@login_required
def nextPage():

    allRecords = user.query.all()

    flash('Hello There') #TESTLINE

    return render_template('next.html', records=allRecords, timestamp = currentTime(), title = 'Database Lookup')

if __name__ == '__main__':
    create_db(bitwiz)
    login_manager.init_app(bitwiz)
# BE SURE TO SWITCH THESE WHEN DOING LOCAL DEVELOPMENT VS. DEPLOYED VERSION
    #bitwiz.run()
    bitwiz.run()  #TESTLINE
