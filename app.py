from flask import Flask, request, jsonify, render_template, url_for, redirect, flash
from flask_cors import CORS
from itsdangerous import URLSafeTimedSerializer
import secrets
from flask_mail import Mail, Message
from flask_login import (
    LoginManager, UserMixin, login_user,
    login_required, logout_user, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash

import csv
import os
import pandas as pd
import json
import smtplib
from email.mime.text import MIMEText
from datetime import datetime

# -------------------- BASIC APP SETUP --------------------
app = Flask(__name__)
app.secret_key = "easygo_super_secret_key"  # move to env var in production
CORS(app)

DATA_DIR = 'data'
os.makedirs(DATA_DIR, exist_ok=True)

INVENTORY_PATH = os.path.join(DATA_DIR, 'inventory.csv')
PHARMACIES_PATH = os.path.join(DATA_DIR, 'pharmacies.csv')
ADMINS_PATH = os.path.join(DATA_DIR, 'admins.csv')
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Ensure inventory file exists with headers if missing
if not os.path.exists(INVENTORY_PATH):
    pd.DataFrame(columns=['Drug Name', 'Pharmacy Name', 'Address', 'Contact', 'Price']).to_csv(INVENTORY_PATH, index=False)

# -------------------- MAIL (Hostinger SMTP) --------------------
app.config['MAIL_SERVER'] = 'smtp.hostinger.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USERNAME'] = 'easygo@easygopharm.com'
app.config['MAIL_PASSWORD'] = 'Easygo@1'  # consider moving to an environment variable
app.config['MAIL_DEFAULT_SENDER'] = ('EasyGo Pharm', 'easygo@easygopharm.com')

mail = Mail(app)
serializer = URLSafeTimedSerializer(app.secret_key)

#----------------FORGOT PASSWORD ROUTE -------------------
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        # Check if the email exists in pharmacies.csv
        with open('data/pharmacies.csv', 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                if row['email'] == email:
                    token = serializer.dumps(email, salt='password-reset')
                    reset_url = url_for('reset_password', token=token, _external=True)

                    msg = Message('Password Reset - EasyGo Pharm',
                                  sender='easygo@easygopharm.com',
                                  recipients=[email])
                    msg.body = f'Click this link to reset your password:\n{reset_url}\n\nThis link expires in 30 minutes.'
                    mail.send(msg)
                    flash('Password reset link has been sent to your email.', 'info')
                    return redirect(url_for('login'))
        flash('Email not found. Please check and try again.', 'danger')
    return render_template('forgot_password.html')

#----------------RESET PASSWORD ROUTE -------------------
@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = serializer.loads(token, salt='password-reset', max_age=1800)
    except:
        flash('The reset link is invalid or expired.', 'danger')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        new_password = request.form['new_password']

        rows = []
        updated = False

        # ✅ Read and update password_hash for the correct user
        with open('data/pharmacies.csv', 'r', newline='', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            fieldnames = reader.fieldnames
            for row in reader:
                if row['email'].lower() == email.lower():
                   # ✅ Hash the new password before saving
                    row['password_hash'] = generate_password_hash(new_password)
                    updated = True
                rows.append(row)

        # ✅ Write updated data back safely
        if updated:
            with open('data/pharmacies.csv', 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(rows)

            flash('Your password has been reset successfully.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Email not found in records.', 'danger')

    return render_template('reset_password.html')



# -------------------- LOGIN MANAGER --------------------
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # default

class User(UserMixin):
    def __init__(self, id, email, name, is_admin=False):
        # id will be like "pharm-<index>" or "admin-<index>"
        self.id = id
        self.email = email
        self.name = name
        self.is_admin = is_admin

@login_manager.user_loader
def load_user(user_id):
    """
    user_id format:
      - pharm-<index>
      - admin-<index>
    """
    try:
        prefix, idx = user_id.split('-', 1)
    except Exception:
        return None

    if prefix == 'pharm':
        # load pharmacies
        if not os.path.exists(PHARMACIES_PATH):
            return None
        with open(PHARMACIES_PATH, newline='', encoding='utf-8') as f:
            reader = list(csv.DictReader(f))
        try:
            idx = int(idx)
            record = reader[idx]
            return User(user_id, record.get('email'), record.get('pharmacy_name'), is_admin=False)
        except Exception:
            return None
    elif prefix == 'admin':
        if not os.path.exists(ADMINS_PATH):
            return None
        with open(ADMINS_PATH, newline='', encoding='utf-8') as f:
            reader = list(csv.DictReader(f))
        try:
            idx = int(idx)
            record = reader[idx]
            return User(user_id, record.get('email'), record.get('name'), is_admin=True)
        except Exception:
            return None
    return None

# -------------------- UTIL: ensure admin exists --------------------
def ensure_admin_exists():
    """
    Create admins.csv with provided admin credentials if it doesn't exist or is empty.
    Admin credentials set here per your instruction.
    """
    if not os.path.exists(ADMINS_PATH) or os.path.getsize(ADMINS_PATH) == 0:
        admin_email = "easygo@easygopharm.com"
        admin_password_plain = "Easygo@1"
        hashed = generate_password_hash(admin_password_plain)
        with open(ADMINS_PATH, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=['email', 'password_hash', 'name'])
            writer.writeheader()
            writer.writerow({'email': admin_email, 'password_hash': hashed, 'name': 'EasyGo Admin'})

ensure_admin_exists()

# -------------------- HELPERS: pharmacies file --------------------
def ensure_pharmacies_file():
    if not os.path.exists(PHARMACIES_PATH):
        with open(PHARMACIES_PATH, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=['email', 'password_hash', 'pharmacy_name', 'address', 'contact'])
            writer.writeheader()

ensure_pharmacies_file()

def read_pharmacies():
    with open(PHARMACIES_PATH, newline='', encoding='utf-8') as f:
        return list(csv.DictReader(f))

def append_pharmacy(email, password_hash, pharmacy_name, address, contact):
    with open(PHARMACIES_PATH, 'a', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['email', 'password_hash', 'pharmacy_name', 'address', 'contact'])
        writer.writerow({
            'email': email,
            'password_hash': password_hash,
            'pharmacy_name': pharmacy_name,
            'address': address,
            'contact': contact
        })

# -------------------- ROUTES: public --------------------
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/services')
def services():
    return render_template('services.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/faq')
def faq():
    return render_template('faq.html')

@app.route('/disclaimer')
def disclaimer():
    return render_template('disclaimer.html')

@app.route('/privacy')
def privacy():
    return render_template('privacy.html')

@app.route('/terms')
def terms():
    return render_template('terms.html')


# Keep your /search route (unchanged behavior)
@app.route('/search')
def search():
    query = request.args.get('q', '').lower()
    results = []
    csv_path = INVENTORY_PATH
    # read CSV with pandas so it tolerates varying quoting/encoding
    try:
        df = pd.read_csv(csv_path, encoding='utf-8-sig')
    except Exception:
        # fallback to csv module
        with open(csv_path, newline='', encoding='utf-8') as csvfile:
            reader = csv.DictReader(csvfile)
            for item in reader:
                clean_item = {k.strip(): v.strip() for k, v in item.items() if k}
                drug_name = clean_item.get("Drug Name", "").lower()
                if query in drug_name:
                    results.append(clean_item)
        return jsonify(results)

    for _, row in df.iterrows():
        drug_name = str(row.get('Drug Name', '')).lower()
        if query in drug_name:
            results.append({
                'Drug Name': row.get('Drug Name', ''),
                'Pharmacy Name': row.get('Pharmacy Name', ''),
                'Address': row.get('Address', ''),
                'Contact': row.get('Contact', ''),
                'Price': row.get('Price', '')
            })
    return jsonify(results)

# Old /request route (kept; uses smtplib as before)
@app.route("/request", methods=["POST"])
def request_drug():
    data = request.json
    name = data.get("name")
    email = data.get("email")
    phone = data.get("phone")
    drug_name = data.get("drugName")
    dosage = data.get("dosage")
    info = data.get("info")

    subject = f"New Drug Request from {name}"
    body = f"""
You have received a new drug request from EasyGo Pharm:

Name: {name}
Email: {email}
Phone: {phone}
Drug: {drug_name}
Dosage: {dosage}
Additional Info: {info}
"""

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = "easygo@easygopharm.com"
    msg["To"] = "easygo@easygopharm.com"

    try:
        with smtplib.SMTP("smtp.hostinger.com", 587) as server:
            server.starttls()
            server.login("easygo@easygopharm.com", "Easygo@1")
            server.send_message(msg)
        return jsonify({"success": True, "message": "Request sent successfully!"}), 200
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

# -------------------- ROUTES: registration & pharmacy login --------------------
@app.route('/register', methods=['GET', 'POST'])
def register():
    """Pharmacy registration"""
    if request.method == 'POST':
        email = request.form.get('email').strip()
        pharmacy_name = request.form.get('pharmacy_name').strip()
        password = request.form.get('password')
        address = request.form.get('address', '').strip()
        contact = request.form.get('contact', '').strip()

        # basic validation
        if not email or not pharmacy_name or not password:
            flash('Please fill all required fields.', 'danger')
            return redirect(url_for('register'))

        # check existing email
        pharmacies = read_pharmacies()
        for p in pharmacies:
            if p.get('email').lower() == email.lower():
                flash('An account with that email already exists. Please login.', 'warning')
                return redirect(url_for('login'))

        password_hash = generate_password_hash(password)
        append_pharmacy(email, password_hash, pharmacy_name, address, contact)
        flash('Registration successful. Please login.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Pharmacy login"""
    if request.method == 'POST':
        email = request.form.get('email').strip()
        password = request.form.get('password')

        pharmacies = read_pharmacies()
        for i, p in enumerate(pharmacies):
            if p.get('email').lower() == email.lower():
                if check_password_hash(p.get('password_hash', ''), password):
                    user_id = f'pharm-{i}'
                    login_user(User(user_id, p.get('email'), p.get('pharmacy_name'), is_admin=False))
                    return redirect(url_for('pharmacy_dashboard'))
                else:
                    flash('Invalid credentials', 'danger')
                    return redirect(url_for('login'))

        flash('No pharmacy account found with that email. Please register first.', 'warning')
        return redirect(url_for('register'))

    return render_template('login.html')

# -------------------- ROUTES: admin login --------------------
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        email = request.form.get('email').strip()
        password = request.form.get('password')

        # read admins csv
        if os.path.exists(ADMINS_PATH):
            with open(ADMINS_PATH, newline='', encoding='utf-8') as f:
                admins = list(csv.DictReader(f))
        else:
            admins = []

        for i, a in enumerate(admins):
            if a.get('email').lower() == email.lower():
                if check_password_hash(a.get('password_hash', ''), password):
                    user_id = f'admin-{i}'
                    login_user(User(user_id, a.get('email'), a.get('name'), is_admin=True))
                    return redirect(url_for('admin_dashboard'))
                else:
                    flash('Invalid admin credentials', 'danger')
                    return redirect(url_for('admin_login'))

        flash('Admin account not found', 'danger')
        return redirect(url_for('admin_login'))

    return render_template('admin_login.html')

# -------------------- ROUTES: logout --------------------
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    # Redirect smartly based on role
    try:
        if current_user.is_admin:
            return redirect(url_for('admin_login'))
    except Exception:
        pass
    return redirect(url_for('login'))

# -------------------- ROUTES: pharmacy area --------------------
@app.route('/pharmacy/dashboard')
@login_required
def pharmacy_dashboard():
    # only pharmacies
    if current_user.is_admin:
        flash('Admins must use the admin dashboard.', 'warning')
        return redirect(url_for('admin_dashboard'))

    # load inventory and filter
    try:
        df = pd.read_csv(INVENTORY_PATH, encoding='utf-8-sig')
    except Exception:
        df = pd.DataFrame(columns=['Drug Name', 'Pharmacy Name', 'Address', 'Contact', 'Price'])

    pharmacy_name = current_user.name
    pharmacy_df = df[df['Pharmacy Name'] == pharmacy_name]
    table_html = pharmacy_df.to_html(classes='table table-striped', index=False) if not pharmacy_df.empty else "<p>No inventory uploaded yet.</p>"

    return render_template('pharmacy_dashboard.html',
                           pharmacy=pharmacy_name,
                           tables=table_html)

@app.route('/pharmacy/upload_inventory', methods=['GET', 'POST'])
@login_required
def pharmacy_upload_inventory():
    # ensure only pharmacy users
    if current_user.is_admin:
        flash('Admins cannot upload via pharmacy upload. Use admin dashboard.', 'warning')
        return redirect(url_for('admin_dashboard'))

    message = None
    if request.method == 'POST':
        file = request.files.get('file')
        if not file:
            flash('Please upload a CSV file.', 'danger')
            return redirect(url_for('pharmacy_upload_inventory'))

        filepath = os.path.join(UPLOAD_FOLDER, file.filename)
        file.save(filepath)

        try:
            uploaded_df = pd.read_csv(filepath, encoding='utf-8-sig')

            required_columns = ['Drug Name', 'Pharmacy Name', 'Address', 'Contact', 'Price']
            if not all(col in uploaded_df.columns for col in required_columns):
                flash("CSV format is incorrect. Make sure headers: Drug Name, Pharmacy Name, Address, Contact, Price", 'danger')
                return redirect(url_for('pharmacy_upload_inventory'))

            # force pharmacy name to current user's pharmacy name
            uploaded_df['Pharmacy Name'] = current_user.name

            # merge with master inventory
            try:
                main_df = pd.read_csv(INVENTORY_PATH, encoding='utf-8-sig')
            except Exception:
                main_df = pd.DataFrame(columns=required_columns)

            combined_df = pd.concat([main_df, uploaded_df], ignore_index=True)

            # drop duplicates (drug + pharmacy)
            combined_df.drop_duplicates(subset=['Drug Name', 'Pharmacy Name'], keep='last', inplace=True)

            combined_df.to_csv(INVENTORY_PATH, index=False, encoding='utf-8-sig')
            flash('Inventory uploaded successfully.', 'success')

            # send admin notification email
            try:
                record_count = len(uploaded_df)
                msg = Message(
                    subject="New Pharmacy Inventory Upload",
                    recipients=["easygo@easygopharm.com"],
                    body=f"""New inventory uploaded.

Pharmacy: {current_user.name}
Records Uploaded: {record_count}
Uploaded At: {datetime.utcnow().isoformat()} UTC

-- EasyGo Pharm
"""
                )
                mail.send(msg)
            except Exception as e:
                # log failure but don't stop flow
                print("Failed to send upload notification:", e)

            return redirect(url_for('pharmacy_dashboard'))

        except Exception as e:
            flash(f"An error occurred while processing the CSV: {e}", 'danger')
        finally:
            if os.path.exists(filepath):
                os.remove(filepath)

    return render_template('upload_inventory.html', pharmacy=current_user.name)

# -------------------- ROUTES: admin dashboard --------------------
@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash('Access denied: Admins only.', 'danger')
        return redirect(url_for('login'))

    # Load full inventory
    try:
        df = pd.read_csv(INVENTORY_PATH, encoding='utf-8-sig')
    except Exception:
        df = pd.DataFrame(columns=['Drug Name', 'Pharmacy Name', 'Address', 'Contact', 'Price'])

    inventory_table = df.to_html(classes='table table-bordered table-sm', index=False)

    # Load pharmacies list
    pharmacies = read_pharmacies()
    pharm_df = pd.DataFrame(pharmacies)
    pharm_table = pharm_df.to_html(classes='table table-striped table-sm', index=False) if not pharm_df.empty else "<p>No registered pharmacies.</p>"

    return render_template('admin_dashboard.html',
                           inventory_table=inventory_table,
                           pharm_table=pharm_table)

# -------------------- RUN --------------------
if __name__ == "__main__":
    app.run(debug=True)
