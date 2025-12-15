from flask import Flask, render_template, redirect, url_for, request, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'dev-secret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///lost_and_found.db'
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'webp'}

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# ===================== MODELS =====================
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

class Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100))
    description = db.Column(db.Text)
    location = db.Column(db.String(100))
    category = db.Column(db.String(50))
    status = db.Column(db.String(10))  # Lost / Found
    contact = db.Column(db.String(100))
    image = db.Column(db.String(200))
    approved = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ===================== ROUTES =====================
@app.route('/')
def index():
    q = request.args.get('q', '')
    category = request.args.get('category', '')

    query = Item.query.filter_by(approved=True)

    if q:
        query = query.filter(Item.title.contains(q))
    if category:
        query = query.filter_by(category=category)

    items = query.order_by(Item.created_at.desc()).all()
    return render_template('index.html', items=items)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = generate_password_hash(request.form['password'])

        if User.query.filter_by(email=email).first():
            flash('Email already exists')
            return redirect(url_for('register'))

        user = User(email=email, password=password)
        db.session.add(user)
        db.session.commit()
        flash('Account created')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(email=request.form['email']).first()
        if user and check_password_hash(user.password, request.form['password']):
            login_user(user)
            return redirect(url_for('index'))
        flash('Invalid credentials')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/post', methods=['GET', 'POST'])
@login_required
def post_item():
    if request.method == 'POST':
        file = request.files['image']
        filename = None

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        item = Item(
            title=request.form['title'],
            description=request.form['description'],
            location=request.form['location'],
            category=request.form['category'],
            status=request.form['status'],
            contact=request.form['contact'],
            image=filename,
            user_id=current_user.id
        )
        db.session.add(item)
        db.session.commit()
        flash('Item submitted for approval')
        return redirect(url_for('my_items'))
    return render_template('post_item.html')

@app.route('/my-items')
@login_required
def my_items():
    items = Item.query.filter_by(user_id=current_user.id).all()
    return render_template('my_items.html', items=items)

@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:
        abort(403)
    items = Item.query.filter_by(approved=False).all()
    return render_template('admin.html', items=items)

@app.route('/approve/<int:item_id>')
@login_required
def approve(item_id):
    if not current_user.is_admin:
        abort(403)
    item = Item.query.get_or_404(item_id)
    item.approved = True
    db.session.commit()
    return redirect(url_for('admin'))

# ===================== INIT =====================
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(email='admin@student.edu').first():
            admin = User(email='admin@student.edu', password=generate_password_hash('admin123'), is_admin=True)
            db.session.add(admin)
            db.session.commit()
    app.run(debug=True)

