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
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    project_name = db.Column(db.String(50), nullable=False)
    project_description = db.Column(db.String(500), nullable=False)
    project_image = db.Column(db.String(100), nullable=True)
    project_download = db.Column(db.String(100), nullable=True)


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


def create_default_user():
    admin_user = User(username='admin', password=generate_password_hash('password'), isadmin=True, isauthor=True)
    db.session.add(admin_user)
    db.session.commit()


if not os.path.exists('instance/db.db'):
    with app.app_context():
        db.create_all()
        create_default_user()
        print("Datenbank erstellt.")


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/blog')
def blog():
    pass


@app.route('/projects')
def projects():
    project_list = ProjectList.query.all()
    return render_template('projects.html', projects=project_list)


@app.route('/project/<int:id>')
def project(id):
    project_element = ProjectList.query.get(id)
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


@app.route('/add_project', methods=['GET', 'POST'])
def add_project():
    if request.method == 'POST':
        new_project = ProjectList(
            project_name=request.form['project_name'],
            project_description=request.form['project_description'],
            project_image=request.form['project_image'],
            project_download=request.form['project_download']
        )
        db.session.add(new_project)
        db.session.commit()
        return redirect(url_for('projects'))
    return render_template('add_project.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user_in_session = User.query.filter_by(username=username).first()
        if user_in_session and check_password_hash(user_in_session.password, password):
            session['username'] = user_in_session.username
            return redirect(url_for('index'))
        else:
            return render_template('login.html', error="Invalid username or password")
    return render_template('login.html')


@app.route('/user', methods=['GET', 'POST'])
def user():
    if 'username' not in session:
        return redirect(url_for('login'))
    username = session['username']
    user_in_session = User.query.filter_by(username=username).first()
    if request.method == 'POST':
        new_password = request.form['new_password']
        user_in_session.password = generate_password_hash(new_password)
        db.session.commit()
        return render_template('user.html', user=user_in_session, message="Password changed successfully")
    return render_template('user.html', user=user_in_session)


@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('index'))


@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if 'username' not in session:
        return redirect(url_for('login'))
    username = session['username']
    user_in_session = User.query.filter_by(username=username).first()
    if request.method == 'POST':
        new_password = request.form['new_password']
        user_in_session.password = generate_password_hash(new_password)
        db.session.commit()
        return redirect(url_for('user'))
    return render_template('change_password.html', user=user_in_session)


if __name__ == '__main__':
    app.run(debug=True)
