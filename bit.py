from os import path
from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

# Global variable for database
# BE SURE TO SWITCH THESE WHEN DOING LOCAL DEVELOPMENT VS. DEPLOYED VERSION
#DB_NAME = "/home/ec2-user/CMSC-495-Project/cmsc495.db"
DB_NAME = "cmsc495.db" #-- This is used when doing local testing.

bitwiz = Flask(__name__)
bitwiz.config['SECRET_KEY'] = 'WeAreVeryMagical1357913'
bitwiz.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DB_NAME}'
bitwiz.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Call the db.
db = SQLAlchemy(bitwiz)

def create_db(app):
    ''' Function that builds the database'''
    if not path.exists(DB_NAME):
        db.create_all(app=bitwiz)

def currentTime():
    dateTime = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    return dateTime

class user(db.Model):
    userId = db.Column(db.Integer, primary_key=True)
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
    entryId = db.Column(db.Integer, primary_key=True)
    userId = db.Column(db.Integer)
    title = db.Column(db.String(100))
    encryptedPassword = db.Column(db.String(100))
    associatedUrl = db.Column(db.String(100))
    notes = db.Column(db.String(400))
    dateCreated = db.Column(db.Date)
    dateModified = db.Column(db.Time)

class passwordGenerator(db.Model):
    algorithimId = db.Column(db.Integer, primary_key=True)
    algorithim = db.Column(db.String(100))
    length = db.Column(db.Integer)
    useUppercase = db.Column(db.Boolean)
    useLowercase = db.Column(db.Boolean)
    useNumbers = db.Column(db.Boolean)
    useSpeicalChars = db.Column(db.Boolean)

class encryptiionHandler(db.Model):
    algorithimTypeId = db.Column(db.Integer, primary_key=True)
    algorithmType = db.Column(db.String(100))
    encryptionKey = db.Column(db.String(100))

@bitwiz.route('/register', methods=['POST', 'GET'])
def indexPage():
    username = None
    password = None
    salt = None
    question = None
    answer = None

    if request.method == 'POST':
        newUsername = request.form['username']
        newPassword = request.form['password']
        newSalt = request.form['salt']
        newQuestion = request.form['question']
        newAnswer = request.form['answer']

        newRec = user(newUsername, newPassword, newSalt, newQuestion, newAnswer)
        db.session.add(newRec)
        db.session.commit()

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

        # Add the logic for Login

    return render_template('login.html', timestamp = currentTime(), title = 'CMST 495 - BitWizards')

@bitwiz.route('/next', methods=['GET'])
def nextPage():

    allRecords = user.query.all()

    return render_template('next.html', records=allRecords, timestamp = currentTime(), title = 'Database Lookup')


if __name__ == '__main__':
    create_db(bitwiz)
# BE SURE TO SWITCH THESE WHEN DOING LOCAL DEVELOPMENT VS. DEPLOYED VERSION
    #bitwiz.run()
    bitwiz.run(debug=True)
