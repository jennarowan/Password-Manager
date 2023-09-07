from os import path
from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

# Global variable for database
DB_NAME = "cmsc495.db"

bitwiz = Flask(__name__)
bitwiz.config['SECRET_KEY'] = 'WeAreVeryMagical1357913'
bitwiz.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DB_NAME}'
bitwiz.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Call the db.
db = SQLAlchemy(bitwiz)

def create_db(app):
    ''' Function that builds the database'''
    if not path.exists('database/' + DB_NAME):
        db.create_all(app=bitwiz)

def currentTime():
    dateTime = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    return dateTime

class data(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    fullname = db.Column(db.String(100), nullable=False)
    shortname = db.Column(db.String(100))
    password = db.Column(db.String(50))

    def __init__(self, fullname, shortname, password):
        self.fullname = fullname
        self.shortname = shortname
        self.password = password

@bitwiz.route('/', methods=['POST', 'GET'])
def indexPage():
    fullName = None
    shortName = None
    password = None

    if request.method == 'POST':
        fullName = request.form['fullname']
        shortName = request.form['shortname']
        password = request.form['password']

        newRec = data(fullName,shortName,password)
        db.session.add(newRec)
        db.session.commit()

        return redirect(url_for('nextPage'))

    return render_template('index.html', timestamp = currentTime(), title = 'CMST 495 - BitWizards')

@bitwiz.route('/next', methods=['GET'])
def nextPage():

    allRecords = data.query.all()

    return render_template('next.html', records=allRecords, timestamp = currentTime(), title = 'Database Lookup')

if __name__ == '__main__':
    create_db(bitwiz)
    bitwiz.run()
