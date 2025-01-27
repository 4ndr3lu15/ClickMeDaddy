# app.py
from flask import Flask, render_template, request, redirect, url_for, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    clicks = db.Column(db.Integer, default=0)

    def get_rank(self):
        users = User.query.order_by(User.clicks.desc()).all()
        return users.index(self) + 1

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = generate_password_hash(password)
        user = User(username=username, password_hash=hashed_password)
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', user=current_user)

@app.route('/increment', methods=['POST'])
@login_required
def increment():
    current_user.clicks += 1
    db.session.commit()
    return jsonify(clicks=current_user.clicks, rank=current_user.get_rank())

@app.route('/ranking')
@login_required
def ranking():
    users = User.query.order_by(User.clicks.desc()).all()
    return render_template('ranking.html', users=users)

@app.route('/get_rankings')
def get_rankings():
    users = User.query.order_by(User.clicks.desc()).all()
    rankings = [{'username': u.username, 'clicks': u.clicks} for u in users]
    return jsonify(rankings)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
