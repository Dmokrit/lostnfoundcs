import os
import uuid
from datetime import datetime
from flask import (
    Flask, render_template, redirect,
    url_for, request, flash, abort
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin,
    login_user, logout_user,
    login_required, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# ===================== APP SETUP =====================
app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret")

# ===================== DATABASE =====================
DATA_DIR = "/tmp"
os.makedirs(DATA_DIR, exist_ok=True)
app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{DATA_DIR}/lost_and_found.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# ===================== UPLOADS =====================
UPLOAD_FOLDER = os.path.join("static", "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024  # 2MB

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "webp"}

# ===================== EXTENSIONS =====================
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

# ===================== HELPERS =====================
def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

# ===================== MODELS =====================
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

class Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    location = db.Column(db.String(100))
    category = db.Column(db.String(50))
    status = db.Column(db.String(10))  # Lost / Found
    contact = db.Column(db.String(100))
    image = db.Column(db.String(200))
    approved = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ===================== TEMPLATE FILTER =====================
@app.template_filter('formatdatetime')
def format_datetime(value, format="%b %d, %Y %I:%M %p"):
    if value is None:
        return ""
    return value.strftime(format)

# ===================== ROUTES =====================
@app.route("/")
def index():
    # Only approved items on homepage
    items = Item.query.filter_by(approved=True).order_by(Item.created_at.desc()).all()
    return render_template("index.html", items=items)

# ---------------- AUTH ----------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        if User.query.filter_by(email=email).first():
            flash("Email already exists", "error")
            return redirect(url_for("register"))

        user = User(
            email=email,
            password=generate_password_hash(password)
        )
        db.session.add(user)
        db.session.commit()
        flash("Account created. Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = User.query.filter_by(email=request.form["email"]).first()
        if user and check_password_hash(user.password, request.form["password"]):
            login_user(user)
            return redirect(url_for("index"))
        flash("Invalid email or password", "error")
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("index"))

# ---------------- ITEMS ----------------
@app.route("/post", methods=["GET", "POST"])
@login_required
def post_item():
    if request.method == "POST":
        file = request.files.get("image")
        filename = None
        if file and allowed_file(file.filename):
            ext = file.filename.rsplit(".", 1)[1].lower()
            filename = f"{uuid.uuid4().hex}.{ext}"
            file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))

        item = Item(
            title=request.form["title"],
            description=request.form.get("description"),
            location=request.form.get("location"),
            category=request.form.get("category"),
            status=request.form["status"],
            contact=request.form.get("contact"),
            image=filename,
            user_id=current_user.id
        )

        db.session.add(item)
        db.session.commit()
        flash("Item submitted for admin approval.", "success")
        return redirect(url_for("my_items"))

    return render_template("post_item.html")

@app.route("/my-items")
@login_required
def my_items():
    items = Item.query.filter_by(user_id=current_user.id).order_by(Item.created_at.desc()).all()
    return render_template("my_items.html", items=items)

@app.route("/item/<int:item_id>")
@login_required
def item_detail(item_id):
    item = Item.query.get_or_404(item_id)
    # Allow detail view if approved OR owner OR admin
    if not item.approved and item.user_id != current_user.id and not current_user.is_admin:
        abort(404)
    return render_template("item_detail.html", item=item)

# ---------------- USER EDIT/DELETE ----------------
@app.route("/edit/<int:item_id>", methods=["GET", "POST"])
@login_required
def edit_item(item_id):
    item = Item.query.get_or_404(item_id)
    if item.user_id != current_user.id:
        abort(403)
    if request.method == "POST":
        item.title = request.form["title"]
        item.description = request.form.get("description")
        item.location = request.form.get("location")
        item.category = request.form.get("category")
        item.status = request.form["status"]
        item.contact = request.form.get("contact")

        file = request.files.get("image")
        if file and allowed_file(file.filename):
            if item.image:
                # Safely remove old image
                old_path = os.path.join(app.config["UPLOAD_FOLDER"], item.image)
                if os.path.exists(old_path):
                    os.remove(old_path)
            ext = file.filename.rsplit(".", 1)[1].lower()
            item.image = f"{uuid.uuid4().hex}.{ext}"
            file.save(os.path.join(app.config["UPLOAD_FOLDER"], item.image))
        # Optionally handle "remove_image" checkbox
        elif request.form.get("remove_image") == "yes" and item.image:
            old_path = os.path.join(app.config["UPLOAD_FOLDER"], item.image)
            if os.path.exists(old_path):
                os.remove(old_path)
            item.image = None

        item.approved = False  # require re-approval
        db.session.commit()
        flash("Item updated. Pending admin approval.", "success")
        return redirect(url_for("my_items"))

    return render_template("edit_item.html", item=item)

@app.route("/delete/<int:item_id>", methods=["POST"])
@login_required
def delete_item(item_id):
    item = Item.query.get_or_404(item_id)
    if item.user_id != current_user.id:
        abort(403)
    if item.image:
        path = os.path.join(app.config["UPLOAD_FOLDER"], item.image)
        if os.path.exists(path):
            os.remove(path)
    db.session.delete(item)
    db.session.commit()
    flash("Item deleted successfully.", "success")
    return redirect(url_for("my_items"))

# ---------------- ADMIN ----------------
@app.route("/admin")
@login_required
def admin():
    if not current_user.is_admin:
        abort(403)
    items = Item.query.filter_by(approved=False).order_by(Item.created_at.desc()).all()
    return render_template("admin.html", items=items)

@app.route("/approve/<int:item_id>")
@login_required
def approve(item_id):
    if not current_user.is_admin:
        abort(403)
    item = Item.query.get_or_404(item_id)
    item.approved = True
    db.session.commit()
    flash("Item approved.", "success")
    return redirect(url_for("admin"))

@app.route("/admin/delete/<int:item_id>", methods=["POST"])
@login_required
def admin_delete_item(item_id):
    if not current_user.is_admin:
        abort(403)
    item = Item.query.get_or_404(item_id)
    if item.image:
        path = os.path.join(app.config["UPLOAD_FOLDER"], item.image)
        if os.path.exists(path):
            os.remove(path)
    db.session.delete(item)
    db.session.commit()
    flash("Item deleted by admin.", "success")
    return redirect(url_for("admin"))

# ===================== INIT =====================
with app.app_context():
    db.create_all()
    if not User.query.filter_by(email="admin@student.edu").first():
        admin = User(
            email="admin@student.edu",
            password=generate_password_hash("admin123"),
            is_admin=True
        )
        db.session.add(admin)
        db.session.commit()

# ===================== RUN =====================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))

