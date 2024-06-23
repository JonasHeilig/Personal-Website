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
    project_id = db.Column(db.Integer, nullable=False)
    project_name = db.Column(db.String(50), nullable=False)
    project_description = db.Column(db.String(500), nullable=False)
    project_image = db.Column(db.String(100), nullable=False)
    project_download = db.Column(db.String(100), nullable=False)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False)
    password = db.Column(db.String(100), nullable=False)
    isadmin = db.Column(db.Boolean, default=False)
    isauthor = db.Column(db.Boolean, default=False)


class Posts(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, nullable=False)
    post_title = db.Column(db.String(50), nullable=False)
    post_content = db.Column(db.String(500), nullable=False)
    post_image = db.Column(db.String(100), nullable=False)
    post_author = db.Column(db.String(50), nullable=False)


if not os.path.exists('instance/db.db'):
    with app.app_context():
        db.create_all()
        print("Datenbank erstellt.")


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/aboutme')
def aboutme():
    pass


@app.route('/blog')
def blog():
    pass


@app.route('/projects')
def projects():
    project_list = ProjectList.query.all()
    return render_template('projects.html', projects=project_list)


@app.route('/project/<int:project_id>')
def project(project_id):
    project_element = ProjectList.query.filter_by(project_id=project_id).first()
    if project_element is None:
        return render_template('project_not_found.html')
    return render_template('project.html', project=project_element)


@app.route('/download/<int:project_id>')
def download(project_id):
    pass


@app.route('/admin')
def admin():
    pass


@app.route('/write_blog')
def write_article():
    pass


@app.route('/add_project')
def add_project():
    pass


@app.route('/login', methods=['GET', 'POST'])
def login():
    pass


if __name__ == '__main__':
    app.run(debug=True)
