from flask import Flask, render_template, redirect, url_for, request, flash
from datetime import datetime

bitwiz = Flask(__name__)
bitwiz.config['SECRET_KEY'] = 'WeAreVeryMagical1357913'

def currentTime():
    dateTime = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    return dateTime

@bitwiz.route('/')
def indexPage():
    return render_template('index.html', timestamp = currentTime(), title = 'CMST 495 - BitWizards')

if __name__ == '__main__':
    bitwiz.run(debug=True)
