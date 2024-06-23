import os
from flask import Flask, render_template, request, redirect, session, url_for
from flask_sqlalchemy import SQLAlchemy
from flask import send_from_directory
from flask import send_file
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
    project_image = db.Column(db.String(100), nullable=False)
    project_download = db.Column(db.String(100), nullable=True)
    github_link = db.Column(db.String(100), nullable=True)


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


@app.route('/project')
def redirect_to_projects():
    return redirect(url_for('projects'))


@app.route('/project/<int:project_id>')
def project(project_id):
    project_element = ProjectList.query.get(project_id)
    if project_element is None:
        return render_template('project_not_found.html')
    user_in_session = None
    if 'username' in session:
        username = session['username']
        user_in_session = User.query.filter_by(username=username).first()
    return render_template('project.html', project=project_element, user_in_session=user_in_session)


@app.route('/download/<int:project_id>')
def download(project_id):
    project_selected = ProjectList.query.get(project_id)
    if project_selected is None:
        return "Project not found", 404
    directory = 'static/downloads'
    filename = project_selected.project_download
    file_path = os.path.join(directory, filename)
    try:
        return send_file(file_path, as_attachment=True)
    except FileNotFoundError:
        return "File not found", 404


@app.route('/admin')
def admin():
    pass


@app.route('/write_blog')
def write_article():
    pass


@app.route('/add_project', methods=['GET', 'POST'])
def add_project():
    if 'username' not in session:
        return redirect(url_for('login'))
    username = session['username']
    user_in_session = User.query.filter_by(username=username).first()
    if not user_in_session.isauthor:
        return redirect(url_for('projects'))
    if request.method == 'POST':
        github_link = request.form['github_link']
        if not github_link.startswith('https://'):
            github_link = 'https://' + github_link
        new_project = ProjectList(
            project_name=request.form['project_name'],
            project_description=request.form['project_description'],
            project_image=request.form['project_image'],
            project_download=request.form['project_download'],
            github_link=github_link
        )
        db.session.add(new_project)
        db.session.commit()
        return redirect(url_for('projects'))
    return render_template('add_project.html')


@app.route('/edit_project/<int:project_id>', methods=['GET', 'POST'])
def edit_project(project_id):
    if 'username' not in session:
        return redirect(url_for('login'))
    username = session['username']
    user_in_session = User.query.filter_by(username=username).first()
    if not user_in_session.isauthor:
        return redirect(url_for('projects'))
    selected_project = ProjectList.query.get(project_id)
    if selected_project is None:
        return render_template('project_not_found.html')
    if request.method == 'POST':
        github_link = request.form['github_link']
        if not github_link.startswith('https://'):
            github_link = 'https://' + github_link
        selected_project.project_name = request.form['project_name']
        selected_project.project_description = request.form['project_description']
        selected_project.project_image = request.form['project_image']
        selected_project.project_download = request.form['project_download']
        selected_project.github_link = github_link
        db.session.commit()
        return redirect(url_for('projects'))
    return render_template('edit_project.html', project=selected_project)


@app.route('/edit_project', methods=['GET', 'POST'])
def redirect_from_edit_project():
    return redirect(url_for('projects'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'username' in session:
        return redirect(url_for('user'))
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
