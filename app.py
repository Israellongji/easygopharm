from flask import Flask, request, jsonify, render_template, url_for, redirect, flash
from flask_cors import CORS
from itsdangerous import URLSafeTimedSerializer
import secrets
from flask_login import (
    LoginManager, UserMixin, login_user,
    login_required, logout_user, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash

import csv
import os
import pandas as pd
import json
from datetime import datetime
from dotenv import load_dotenv
from werkzeug.utils import secure_filename
from flask_mail import Mail, Message


# Brevo (Sendinblue) SDK
import sib_api_v3_sdk
from sib_api_v3_sdk.rest import ApiException
import base64 # for encoding attachments

#Google Cloud API
import gspread
from google.oauth2.service_account import Credentials



# -------------------- CONFIG & APP SETUP --------------------
# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "easygo_super_secret_key")
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

# -------------------- BREVO EMAIL SETUP --------------------
BREVO_API_KEY = os.getenv("BREVO_API_KEY")
BREVO_SENDER = os.getenv("BREVO_SENDER_EMAIL", "easygo@easygopharm.com")

if not BREVO_API_KEY:
    print("WARNING: BREVO_API_KEY not set. Email sending will fail unless this is provided in environment.")

brevo_config = sib_api_v3_sdk.Configuration()
if BREVO_API_KEY:
    brevo_config.api_key['api-key'] = BREVO_API_KEY
brevo_api = sib_api_v3_sdk.TransactionalEmailsApi(sib_api_v3_sdk.ApiClient(brevo_config))

def send_email_via_brevo(subject: str, html_body: str, to_emails, attachments=None):
    """
    Send one or more emails using Brevo transactional API.
    to_emails: string or list of strings
    Returns True on success, False on failure.
    """
    if isinstance(to_emails, str):
        to_emails = [to_emails]
    to_list = [{"email": e} for e in to_emails]

    try:
        send_smtp_email = sib_api_v3_sdk.SendSmtpEmail(
            to=to_list,
            sender={"email": BREVO_SENDER, "name": "EasyGo Pharm"},
            subject=subject,
            html_content=html_body,
            attachment=attachments if attachments else None
        )
        response = brevo_api.send_transac_email(send_smtp_email)
        # If no exception, assume success
        print("✅ Brevo email sent:", response)
        return True
    except ApiException as e:
        # print response for debugging
        print("Brevo ApiException:", e)
        try:
            # attempt to print body if available
            print("Brevo response body:", e.body)
        except Exception:
            pass
        return False
    except Exception as ex:
        print("Brevo send error:", ex)
        return False

# -------------------- TOKEN SERIALIZER --------------------
serializer = URLSafeTimedSerializer(app.secret_key)

# -------------------- LOGIN MANAGER --------------------
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # default

class User(UserMixin):
    def __init__(self, id, email, name, is_admin=False):
        self.id = id
        self.email = email
        self.name = name
        self.is_admin = is_admin

@login_manager.user_loader
def load_user(user_id):
    try:
        prefix, idx = user_id.split('-', 1)
    except Exception:
        return None

    if prefix == 'pharm':
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
    Admin credentials come from env or fallback to defaults.
    """
    admin_email = os.getenv("ADMIN_EMAIL", "easygo@easygopharm.com")
    admin_password_plain = os.getenv("ADMIN_PASSWORD", "Easygo@1")
    if not os.path.exists(ADMINS_PATH) or os.path.getsize(ADMINS_PATH) == 0:
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

# -------------------- ROUTES: public pages --------------------
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

# -------------------- SEARCH ROUTE --------------------
@app.route('/search')
def search():
    query = request.args.get('q', '').lower()
    results = []
    csv_path = INVENTORY_PATH
    try:
        df = pd.read_csv(csv_path, encoding='utf-8-sig')
    except Exception:
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

# -------------------- REQUEST ROUTE (uses Brevo) --------------------
@app.route("/request", methods=["POST"])
def request_drug():
    name = request.form.get("name", "")
    email = request.form.get("email", "")
    phone = request.form.get("phone", "")
    drug_name = request.form.get("drug", "")
    dosage = request.form.get("dosage", "")
    info = request.form.get("info", "")
    file = request.files.get("prescription")

    subject = f"New Drug Request from {name or 'Anonymous'}"
    body = f"""
    <h3>New drug request — EasyGo Pharm</h3>
    <p><strong>Name:</strong> {name}</p>
    <p><strong>Email:</strong> {email}</p>
    <p><strong>Phone:</strong> {phone}</p>
    <p><strong>Drug:</strong> {drug_name}</p>
    <p><strong>Dosage:</strong> {dosage}</p>
    <p><strong>Additional Info:</strong> {info}</p>
    <p>Submitted at: {datetime.utcnow().isoformat()} UTC</p>
    """

    # Handle file upload and prepare for Brevo
    attachments = []
    if file:
        filename = secure_filename(file.filename)
        file_content = file.read()
        file_base64 = base64.b64encode(file_content).decode("utf-8")
        attachments.append({
            "name": filename,
            "content": file_base64
        })

    admin_email = os.getenv("ADMIN_EMAIL", "easygo@easygopharm.com")

    # Send to admin and user
    success_admin = send_email_via_brevo(subject, body, admin_email, attachments=attachments)
    user_subject = "EasyGo Pharm - Request Received"
    user_body = f"""
    <h3>Hi {name},</h3>
    <p>We’ve received your drug request and will get back to you shortly.</p>
    <p><b>Drug:</b> {drug_name}</p>
    <p><b>Dosage:</b> {dosage}</p>
    <p><b>Email:</b> {email}</p>
    <p><b>Phone:</b> {phone}</p>
    <p><b>Info:</b> {info}</p>
    <p>Thank you for using <strong>EasyGo Pharm</strong>.</p>
    """
    success_user = send_email_via_brevo(user_subject, user_body, email)

    if success_admin or success_user:
        return jsonify({"success": True, "message": "Request sent successfully!"}), 200
    else:
        return jsonify({"success": False, "error": "Failed to send email"}), 500

# -------------------- FORGOT PASSWORD / RESET (Brevo) --------------------
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        if not email:
            flash('Please provide your registered email.', 'warning')
            return redirect(url_for('forgot_password'))

        found = False
        with open(PHARMACIES_PATH, 'r', newline='', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                if row.get('email', '').lower() == email.lower():
                    found = True
                    token = serializer.dumps(email, salt='password-reset')
                    reset_url = url_for('reset_password', token=token, _external=True)
                    body = f"""
<p>Click the link below to reset your EasyGo Pharm password (expires in 30 minutes):</p>
<p><a href="{reset_url}">{reset_url}</a></p>
"""
                    if send_email_via_brevo("Password Reset - EasyGo Pharm", body, email):
                        flash('Password reset link has been sent to your email.', 'info')
                    else:
                        flash('Failed to send reset email. Try again later.', 'danger')
                    break
        if not found:
            flash('Email not found. Please check and try again.', 'danger')
        return redirect(url_for('login'))

    return render_template('forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = serializer.loads(token, salt='password-reset', max_age=1800)
    except Exception:
        flash('The reset link is invalid or expired.', 'danger')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        new_password = request.form.get('new_password', '')
        if not new_password:
            flash('Please enter a new password.', 'warning')
            return redirect(url_for('reset_password', token=token))

        rows = []
        updated = False
        with open(PHARMACIES_PATH, 'r', newline='', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            fieldnames = reader.fieldnames
            for row in reader:
                if row.get('email', '').lower() == email.lower():
                    row['password_hash'] = generate_password_hash(new_password)
                    updated = True
                rows.append(row)

        if updated:
            with open(PHARMACIES_PATH, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(rows)
            flash('Your password has been reset successfully.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Email not found in records.', 'danger')
            return redirect(url_for('forgot_password'))

    return render_template('reset_password.html')

# -------------------- ROUTES: registration & pharmacy login --------------------
# -------------------- GOOGLE SHEETS SETUP --------------------
# Use the correct full set of scopes
scope = [
    "https://www.googleapis.com/auth/spreadsheets",
    "https://www.googleapis.com/auth/drive"
]

# Load the service account with full drive and sheets access
creds = Credentials.from_service_account_file(
    "service_account.json",
    scopes=scope
)

# Authorize the gspread client
client = gspread.authorize(creds)

# Replace with your Google Sheet name
SHEET_NAME = "EasyGo Pharm Database"
sheet = client.open(SHEET_NAME).sheet1

# -------------------- REGISTER ROUTE --------------------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        pharmacy_name = request.form.get('pharmacy_name', '').strip()
        password = request.form.get('password', '')
        address = request.form.get('address', '').strip()
        contact = request.form.get('contact', '').strip()

        if not email or not pharmacy_name or not password:
            flash('Please fill all required fields.', 'danger')
            return redirect(url_for('register'))

        pharmacies = read_pharmacies()
        for p in pharmacies:
            if p.get('email', '').lower() == email.lower():
                flash('An account with that email already exists. Please login.', 'warning')
                return redirect(url_for('login'))

        password_hash = generate_password_hash(password)
        append_pharmacy(email, password_hash, pharmacy_name, address, contact)
        flash('Registration successful. Please login.', 'success')

        # === 🧾 Add Pharmacy Data to Google Sheet ===
        try:
            sheet.append_row([
                pharmacy_name,
                email,
                password_hash,
                address,
                contact,
                datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
            ])
            print(f"✅ Added {pharmacy_name} to Google Sheet")
        except Exception as e:
            print(f"⚠️ Error adding to Google Sheet: {e}")

        # === 📧 Send Notification Emails ===
        admin_email = "easygo@easygopharm.com"
        email = email  # pharmacy email

        try:
            # Email to Pharmacy (Welcome)
            pharmacy_subject = "Welcome to EasyGo Pharm!"
            pharmacy_message = f"""
            Hi {pharmacy_name},<br><br>
            Welcome to <b>EasyGo Pharm!</b> Your pharmacy account has been successfully registered.<br><br>
            <b>Pharmacy Name:</b> {pharmacy_name}<br>
            <b>Email:</b> {email}<br>
            <b>Contact:</b> {contact}<br>
            <b>Address:</b> {address}<br><br>
            You can now log in and start using EasyGo Pharm.<br><br>
            Best regards,<br>
            <b>EasyGo Pharm Team</b>
            """

            send_email_via_brevo(pharmacy_subject, pharmacy_message, email)

            # Email to Admin (Notification)
            admin_subject = "New Pharmacy Registration - EasyGo Pharm"
            admin_message = f"""
            <h3>New Pharmacy Registration</h3>
            <p><b>Pharmacy Name:</b> {pharmacy_name}</p>
            <p><b>Email:</b> {email}</p>
            <p><b>Address:</b> {address}</p>
            <p><b>Contact:</b> {contact}</p>
            <p><b>Registered at:</b> {datetime.utcnow().isoformat()} UTC</p>
            """

            send_email_via_brevo(admin_subject, admin_message, admin_email)

        except Exception as e:
            print(f"Error sending registration emails: {e}")

        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')

        pharmacies = read_pharmacies()
        for i, p in enumerate(pharmacies):
            if p.get('email', '').lower() == email.lower():
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

# -------------------- ADMIN LOGIN --------------------
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')

        if os.path.exists(ADMINS_PATH):
            with open(ADMINS_PATH, newline='', encoding='utf-8') as f:
                admins = list(csv.DictReader(f))
        else:
            admins = []

        for i, a in enumerate(admins):
            if a.get('email', '').lower() == email.lower():
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

# -------------------- LOGOUT --------------------
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    try:
        if current_user.is_admin:
            return redirect(url_for('admin_login'))
    except Exception:
        pass
    return redirect(url_for('login'))

# -------------------- PHARMACY DASHBOARD & UPLOAD --------------------
@app.route('/pharmacy/dashboard')
@login_required
def pharmacy_dashboard():
    if current_user.is_admin:
        flash('Admins must use the admin dashboard.', 'warning')
        return redirect(url_for('admin_dashboard'))

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
    if current_user.is_admin:
        flash('Admins cannot upload via pharmacy upload. Use admin dashboard.', 'warning')
        return redirect(url_for('admin_dashboard'))

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

            uploaded_df['Pharmacy Name'] = current_user.name

            try:
                main_df = pd.read_csv(INVENTORY_PATH, encoding='utf-8-sig')
            except Exception:
                main_df = pd.DataFrame(columns=required_columns)

            combined_df = pd.concat([main_df, uploaded_df], ignore_index=True)
            combined_df.drop_duplicates(subset=['Drug Name', 'Pharmacy Name'], keep='last', inplace=True)
            combined_df.to_csv(INVENTORY_PATH, index=False, encoding='utf-8-sig')
            flash('Inventory uploaded successfully.', 'success')

            # send admin notification via Brevo
            record_count = len(uploaded_df)
            subject = "New Pharmacy Inventory Upload"
            body = f"""
<p>New inventory uploaded.</p>
<p><strong>Pharmacy:</strong> {current_user.name}</p>
<p><strong>Records Uploaded:</strong> {record_count}</p>
<p><strong>Uploaded At (UTC):</strong> {datetime.utcnow().isoformat()}</p>
"""
            admin_email = os.getenv("ADMIN_EMAIL", "easygo@easygopharm.com")
            if not send_email_via_brevo(subject, body, admin_email):
                print("Failed to send upload notification email via Brevo")

            return redirect(url_for('pharmacy_dashboard'))

        except Exception as e:
            flash(f"An error occurred while processing the CSV: {e}", 'danger')
        finally:
            if os.path.exists(filepath):
                os.remove(filepath)

    return render_template('upload_inventory.html', pharmacy=current_user.name)

# -------------------- ADMIN DASHBOARD --------------------
@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash('Access denied: Admins only.', 'danger')
        return redirect(url_for('login'))

    try:
        df = pd.read_csv(INVENTORY_PATH, encoding='utf-8-sig')
    except Exception:
        df = pd.DataFrame(columns=['Drug Name', 'Pharmacy Name', 'Address', 'Contact', 'Price'])

    inventory_table = df.to_html(classes='table table-bordered table-sm', index=False)

    pharmacies = read_pharmacies()
    pharm_df = pd.DataFrame(pharmacies)
    pharm_table = pharm_df.to_html(classes='table table-striped table-sm', index=False) if not pharm_df.empty else "<p>No registered pharmacies.</p>"

    return render_template('admin_dashboard.html',
                           inventory_table=inventory_table,
                           pharm_table=pharm_table)

# -------------------- RUN --------------------
if __name__ == "__main__":
    app.run(debug=True)