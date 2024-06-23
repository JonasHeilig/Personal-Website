import os
from flask import Flask, render_template, request, redirect, session, url_for
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ECHO'] = True
app.secret_key = 'secret_salt'  # Change this on Public build!
db = SQLAlchemy(app)


class ProjectList(db.Model):
    id = db.Column(db.Integer, primary_key=True)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)


class Posts(db.Model):
    id = db.Column(db.Integer, primary_key=True)


if not os.path.exists('instance/db.db'):
    with app.app_context():
        db.create_all()
        print("Datenbank erstellt.")


@app.route('/')
def index():
    return render_template('index.html')


if __name__ == '__main__':
    app.run(debug=True)
