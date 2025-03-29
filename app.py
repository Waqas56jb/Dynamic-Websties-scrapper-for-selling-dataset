from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_file
import mysql.connector
import os
import csv
import re
import base64
from werkzeug.utils import secure_filename
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import requests
from transformers import pipeline
from geotext import GeoText
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
import time
import pickle
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from flask import jsonify
from datetime import datetime

# Initialize Flask app
app = Flask(__name__)
app.secret_key = 'your_secret_key'
app.config['UPLOAD_FOLDER'] = 'static/uploads'
UPLOAD_FOLDER = 'data'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

from mysql.connector import Error

def get_db_connection():
    try:
        db = mysql.connector.connect(
            host='127.0.0.1',
            user='root',
            password='1234',
            database='user_management_system'
        )
        return db
    except Error as e:
        print(f"Error connecting to MySQL: {e}")
        return None

# Use this function to get a connection whenever needed
db = get_db_connection()
if db is None:
    print("Failed to connect to the database. Exiting...")
    exit(1)

# Load the NER pipeline with a pretrained model
ner_pipeline = pipeline("ner", model="dbmdz/bert-large-cased-finetuned-conll03-english", aggregation_strategy="simple")

# Regex patterns for extracting information
phone_number_regex = r"(?:\+44\s?20\s?\d{4}\s?\d{4}|\+44\s?7\d{3}\s?\d{6}|\+1\s?\(\d{3}\)\s?\d{3}-\d{4}|\+1\s?800\s?\d{3}-\d{4})"
email_regex = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
uk_postal_code_regex = r"\b[A-Z]{1,2}\d{1,2}[A-Z]?\s?\d[A-Z]{2}\b"
us_zip_code_regex = r"\b\d{5}(?:-\d{4})?\b"

# Gmail API Scopes
SCOPES = ['https://www.googleapis.com/auth/gmail.compose']

# Add this function to track email status
def track_email_status(user_email, recipient_email, status):
    cursor = db.cursor()
    cursor.execute(
        "INSERT INTO email_status (user_email, email, status) VALUES (%s, %s, %s)",
        (user_email, recipient_email, status)
    )
    db.commit()

# Helper functions
def clean_organization_names(org_names):
    cleaned = [re.sub(r"[#]+", "", org).strip() for org in org_names]
    return list(set(cleaned))

def extract_entities(text):
    entities = ner_pipeline(text)
    organizations = [entity['word'] for entity in entities if entity['entity_group'] == 'ORG']
    persons = [entity['word'] for entity in entities if entity['entity_group'] == 'PER']
    return {
        "organizations": clean_organization_names(organizations),
        "persons": list(set(persons))
    }

def scrape_url(url):
    try:
        response = requests.get(url, timeout=10)
        soup = BeautifulSoup(response.content, "html.parser")
        text = soup.get_text()

        emails = re.findall(email_regex, text)
        phone_numbers = re.findall(phone_number_regex, text)
        uk_postal_codes = re.findall(uk_postal_code_regex, text)
        us_zip_codes = re.findall(us_zip_code_regex, text)

        geo_data = GeoText(text)
        locations = list(set(geo_data.cities + geo_data.countries))
        postal_codes = list(set(uk_postal_codes + us_zip_codes))

        entities = extract_entities(text)
        person_names = entities["persons"]
        organization_names = entities["organizations"]

        return {
            "url": url,
            "emails": ", ".join(set(emails)),
            "phone_numbers": ", ".join(set(phone_numbers)),
            "postal_codes": ", ".join(postal_codes),
            "locations": ", ".join(locations),
            "person_names": ", ".join(person_names),
            "organization_names": ", ".join(organization_names),
        }
    except Exception as e:
        return {
            "url": url,
            "emails": "",
            "phone_numbers": "",
            "postal_codes": "",
            "locations": "",
            "person_names": "",
            "organization_names": "",
        }

def extract_all_links(url):
    try:
        response = requests.get(url, timeout=10)
        soup = BeautifulSoup(response.content, "html.parser")
        return {
            urljoin(url, a['href'])
            for a in soup.find_all("a", href=True)
            if urlparse(urljoin(url, a['href'])).scheme in ["http", "https"]
        }
    except Exception:
        return set()

def scrape_urls(base_url):
    urls = extract_all_links(base_url)
    all_data = [scrape_url(url) for url in urls]
    return all_data

def credentials_to_dict(credentials):
    return {
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': credentials.scopes
    }

# Routes
@app.route('/')
def index():
    if 'user_id' in session:
        cursor = db.cursor(dictionary=True)
        cursor.execute("SELECT id, name, email, bio, profile_photo FROM users WHERE id = %s", (session['user_id'],))
        user = cursor.fetchone()
        if user:
            return render_template('index.html', user=user)
    return redirect(url_for('login'))

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    cursor = db.cursor(dictionary=True)
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        bio = request.form['bio']
        profile_photo = request.files.get('profile_photo')

        cursor.execute("SELECT id FROM users WHERE email = %s AND id != %s", (email, session['user_id']))
        existing_user = cursor.fetchone()

        if existing_user:
            flash('A user with this email already exists. Please choose a unique email.', 'error')
            return redirect(url_for('profile'))

        if profile_photo:
            filename = secure_filename(profile_photo.filename)
            profile_photo.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            cursor.execute("UPDATE users SET name = %s, email = %s, bio = %s, profile_photo = %s WHERE id = %s",
                           (name, email, bio, filename, session['user_id']))
        else:
            cursor.execute("UPDATE users SET name = %s, email = %s, bio = %s WHERE id = %s",
                           (name, email, bio, session['user_id']))
        db.commit()
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('profile'))

    cursor.execute("SELECT id, name, email, bio, profile_photo FROM users WHERE id = %s", (session['user_id'],))
    user = cursor.fetchone()
    cursor.close()
    return render_template('profile.html', user=user)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        cursor = db.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE email = %s AND password = %s", (email, password))
        user = cursor.fetchone()
        if user:
            session['user_id'] = user['id']
            return redirect(url_for('index'))
        return "Invalid credentials"
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        phone = request.form['phone']
        password = request.form['password']
        profile_photo = request.files['profile_photo']
        filename = secure_filename(profile_photo.filename)
        profile_photo.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        cursor = db.cursor()
        cursor.execute("INSERT INTO users (name, email, phone, password, profile_photo) VALUES (%s, %s, %s, %s, %s)",
                       (name, email, phone, password, filename))
        db.commit()
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        cursor = db.cursor(dictionary=True)
        cursor.execute("SELECT * FROM admin WHERE email = %s AND password = %s", (email, password))
        admin = cursor.fetchone()
        if admin:
            session['admin_id'] = admin['id']
            return redirect(url_for('admin_dashboard'))
        return "Invalid credentials"
    return render_template('admin_login.html')

@app.route('/admin/dashboard')
def admin_dashboard():
    if 'admin_id' in session:
        return render_template('admin_dashboard.html')
    return redirect(url_for('admin_login'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/filter_on_data')
def filters_on_save_data():
    return render_template("filters.html")

@app.route("/home")
def home_page():
    return render_template("Home.html")

@app.route("/scrap")
def scrap_page():
    return render_template("scrap.html")

@app.route("/scrape", methods=["POST"])
def scrape():
    data = request.get_json()
    base_url = data.get("url", "").strip()
    if not base_url:
        return jsonify({"message": "Please provide a valid URL to scrape."}), 400

    results = scrape_urls(base_url)

    user_csv_file = os.path.join(UPLOAD_FOLDER, f'scraped_data_{session["user_id"]}.csv')
    file_exists = os.path.exists(user_csv_file)
    with open(user_csv_file, "a", newline="", encoding="utf-8") as csvfile:
        fieldnames = ["url", "emails", "phone_numbers", "postal_codes", "locations", "person_names", "organization_names"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        if not file_exists:
            writer.writeheader()

        writer.writerows(results)

    return jsonify({
        "message": f"Scraping complete! {len(results)} URLs scraped. You can download the CSV file now.",
        "scrapedResults": results
    })

@app.route("/view_data")
def view_data():
    user_csv_file = os.path.join(UPLOAD_FOLDER, f'scraped_data_{session["user_id"]}.csv')
    if os.path.exists(user_csv_file):
        with open(user_csv_file, "r", encoding="utf-8") as csvfile:
            reader = csv.DictReader(csvfile)
            data = [row for row in reader]
    else:
        data = []

    return render_template("view_data.html", data=data)

@app.route("/filter_data", methods=["POST"])
def filter_data():
    filters = request.json.get("filters", [])
    search_query = request.json.get("query", "").strip().lower()

    user_csv_file = os.path.join(UPLOAD_FOLDER, f'scraped_data_{session["user_id"]}.csv')
    if os.path.exists(user_csv_file):
        with open(user_csv_file, "r", encoding="utf-8") as csvfile:
            reader = csv.DictReader(csvfile)
            data = [row for row in reader]
    else:
        data = []

    if search_query:
        data = [row for row in data if any(search_query in str(row[key]).lower() for key in row)]

    filtered_data = []
    for row in data:
        filtered_row = {key: row[key] for key in filters if key in row}
        filtered_data.append(filtered_row)

    return jsonify(filtered_data)

@app.route("/count_data", methods=["POST"])
def count_data():
    count_query = request.json.get("query", "").strip().lower()

    user_csv_file = os.path.join(UPLOAD_FOLDER, f'scraped_data_{session["user_id"]}.csv')
    if os.path.exists(user_csv_file):
        with open(user_csv_file, "r", encoding="utf-8") as csvfile:
            reader = csv.DictReader(csvfile)
            data = [row for row in reader]
    else:
        data = []

    count = 0
    for row in data:
        if any(count_query in str(row[key]).lower() for key in row):
            count += 1

    return jsonify({"count": count})

@app.route("/download_filtered", methods=["POST"])
def download_filtered():
    filters = request.json.get("filters", [])  # List of columns to include
    search_query = request.json.get("query", "").strip().lower()

    user_csv_file = os.path.join(UPLOAD_FOLDER, f'scraped_data_{session["user_id"]}.csv')
    if os.path.exists(user_csv_file):
        with open(user_csv_file, "r", encoding="utf-8") as csvfile:
            reader = csv.DictReader(csvfile)
            data = [row for row in reader]
    else:
        data = []

    if search_query:
        data = [row for row in data if any(search_query in str(row[key]).lower() for key in row)]

    # Filter columns
    filtered_data = [{key: row[key] for key in filters if key in row} for row in data]

    # Save filtered data to a temporary CSV file
    temp_csv_file = os.path.join(UPLOAD_FOLDER, 'filtered_data.csv')
    with open(temp_csv_file, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=filters)
        writer.writeheader()
        writer.writerows(filtered_data)

    return send_file(temp_csv_file, as_attachment=True)

@app.route("/authorize")
def authorize():
    flow = InstalledAppFlow.from_client_secrets_file(
        'credentials.json',
        scopes=SCOPES,
        redirect_uri=url_for('oauth2callback', _external=True)
    )
    authorization_url, state = flow.authorization_url(access_type='offline', include_granted_scopes='true')
    session['state'] = state
    return redirect(authorization_url)

@app.route("/oauth2callback")
def oauth2callback():
    state = session['state']
    flow = InstalledAppFlow.from_client_secrets_file(
        'credentials.json',
        scopes=SCOPES,
        state=state,
        redirect_uri=url_for('oauth2callback', _external=True)
    )
    flow.fetch_token(authorization_response=request.url)
    credentials = flow.credentials
    session['credentials'] = credentials_to_dict(credentials)
    return redirect(url_for('view_data'))

valid_recipients = []  # Initialize as an empty list

# Define batch size for parallel processing
BATCH_SIZE = 5

# Authenticate and get the credentials
def authenticate_gmail():
    creds = None
    token_path = "token.pickle"

    if os.path.exists(token_path):
        with open(token_path, "rb") as token:
            creds = pickle.load(token)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file("credentials.json", SCOPES)
            creds = flow.run_local_server(port=0)

        with open(token_path, "wb") as token:
            pickle.dump(creds, token)

    return creds

# Create email message
def create_message(sender, to, cc, bcc, subject, body):
    message = MIMEMultipart()
    message["To"] = ", ".join(to)
    message["Cc"] = ", ".join(cc) if cc else ""
    message["Bcc"] = ", ".join(bcc) if bcc else ""
    message["Subject"] = subject

    msg = MIMEText(body)
    message.attach(msg)

    raw_message = base64.urlsafe_b64encode(message.as_bytes()).decode()
    return {"raw": raw_message}

# Send a single email
def send_email(service, sender, to, cc, bcc, subject, body):
    try:
        message = create_message(sender, [to], cc, bcc, subject, body)
        service.users().messages().send(userId="me", body=message).execute()
        print(f"Message sent to {to}")
        return 'Success', to
    except HttpError as error:
        print(f"Error sending email to {to}: {error}")
        return 'Failed', to

# Send emails in parallel
def send_bulk_email(subject, body, recipients, cc, bcc, user_email):
    creds = authenticate_gmail()
    service = build("gmail", "v1", credentials=creds)
    sender = user_email  # Use the logged-in user's email as the sender

    status_tracker = {
        'Success': [],
        'Failed': [],
        'Not Sent': []
    }

    # Split recipients into batches
    batches = [recipients[i:i + BATCH_SIZE] for i in range(0, len(recipients), BATCH_SIZE)]

    with ThreadPoolExecutor(max_workers=5) as executor:
        future_to_recipient = {}

        for batch in batches:
            for recipient in batch:
                future = executor.submit(send_email, service, sender, recipient, cc, bcc, subject, body)
                future_to_recipient[future] = recipient

        for future in as_completed(future_to_recipient):
            status, recipient = future.result()
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            time.sleep(1)  # Avoid hitting rate limits

            if status == 'Success':
                status_tracker['Success'].append((recipient, timestamp))
                track_email_status(user_email, recipient, 'sent')
            elif status == 'Failed':
                status_tracker['Failed'].append((recipient, timestamp))
                track_email_status(user_email, recipient, 'failed')
            else:
                status_tracker['Not Sent'].append((recipient, timestamp))
                track_email_status(user_email, recipient, 'not sent')

            print(f"Email status for {recipient} at {timestamp}: {status}")

    return status_tracker

# API Endpoint to send emails from UI
@app.route("/send_emails", methods=["POST"])
def send_emails():
    data = request.json
    recipients = data.get("recipients", [])
    cc = data.get("cc", [])
    bcc = data.get("bcc", [])
    subject = data.get("subject", "")
    body = data.get("body", "")

    if not recipients:
        return jsonify({"message": "No recipient emails provided."}), 400

    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"message": "User not logged in."}), 401

    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT email FROM users WHERE id = %s", (user_id,))
    user = cursor.fetchone()
    if not user:
        return jsonify({"message": "User not found."}), 404

    user_email = user['email']

    try:
        status_tracker = send_bulk_email(subject, body, recipients, cc, bcc, user_email)
        return jsonify({"message": "Emails sent successfully!", "status": status_tracker}), 200
    except Exception as e:
        return jsonify({"message": f"Error: {e}"}), 500

@app.route("/get_email_status", methods=["GET"])
def get_email_status():
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"message": "User not logged in."}), 401

    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT email FROM users WHERE id = %s", (user_id,))
    user = cursor.fetchone()
    if not user:
        return jsonify({"message": "User not found."}), 404

    cursor.execute("SELECT status, COUNT(*) as count FROM email_status WHERE user_email = %s GROUP BY status", (user['email'],))
    return jsonify(cursor.fetchall())

@app.route("/get_email_records", methods=["GET"])
def get_email_records():
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"message": "User not logged in."}), 401

    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT email FROM users WHERE id = %s", (user_id,))
    user = cursor.fetchone()
    if not user:
        return jsonify({"message": "User not found."}), 404

    cursor.execute("SELECT email, status FROM email_status WHERE user_email = %s", (user['email'],))
    return jsonify(cursor.fetchall())

@app.route("/search_data", methods=["POST"])
def search_data():
    search_query = request.json.get("query", "").strip().lower()

    user_csv_file = os.path.join(UPLOAD_FOLDER, f'scraped_data_{session["user_id"]}.csv')
    if os.path.exists(user_csv_file):
        with open(user_csv_file, "r", encoding="utf-8") as csvfile:
            reader = csv.DictReader(csvfile)
            data = [row for row in reader]
    else:
        data = []

    if search_query:
        data = [row for row in data if any(search_query in str(row[key]).lower() for key in row)]

    return jsonify(data)

@app.route("/sort_data", methods=["POST"])
def sort_data():
    sort_column = request.json.get("column", "url")
    sort_order = request.json.get("order", "asc")  # "asc" or "desc"

    user_csv_file = os.path.join(UPLOAD_FOLDER, f'scraped_data_{session["user_id"]}.csv')
    if os.path.exists(user_csv_file):
        with open(user_csv_file, "r", encoding="utf-8") as csvfile:
            reader = csv.DictReader(csvfile)
            data = [row for row in reader]
    else:
        data = []

    # Sort data
    reverse = sort_order == "desc"
    data = sorted(data, key=lambda x: x.get(sort_column, ""), reverse=reverse)

    return jsonify(data)

@app.route("/select_rows", methods=["POST"])
def select_rows():
    selected_indices = request.json.get("indices", [])  # List of row indices to select

    user_csv_file = os.path.join(UPLOAD_FOLDER, f'scraped_data_{session["user_id"]}.csv')
    if os.path.exists(user_csv_file):
        with open(user_csv_file, "r", encoding="utf-8") as csvfile:
            reader = csv.DictReader(csvfile)
            data = [row for row in reader]
    else:
        data = []

    selected_data = [data[i] for i in selected_indices if i < len(data)]

    return jsonify(selected_data)

@app.route("/drop_columns", methods=["POST"])
def drop_columns():
    columns_to_drop = request.json.get("columns", [])  # List of columns to drop

    user_csv_file = os.path.join(UPLOAD_FOLDER, f'scraped_data_{session["user_id"]}.csv')
    if os.path.exists(user_csv_file):
        with open(user_csv_file, "r", encoding="utf-8") as csvfile:
            reader = csv.DictReader(csvfile)
            data = [row for row in reader]
    else:
        data = []

    # Drop columns
    filtered_data = [{key: row[key] for key in row if key not in columns_to_drop} for row in data]

    return jsonify(filtered_data)

@app.route("/edit_data", methods=["POST"])
def edit_data():
    row_index = request.json.get("index", -1)  # Index of the row to edit
    new_data = request.json.get("data", {})  # New data for the row

    user_csv_file = os.path.join(UPLOAD_FOLDER, f'scraped_data_{session["user_id"]}.csv')
    if os.path.exists(user_csv_file):
        with open(user_csv_file, "r", encoding="utf-8") as csvfile:
            reader = csv.DictReader(csvfile)
            data = [row for row in reader]
    else:
        data = []

    if 0 <= row_index < len(data):
        data[row_index].update(new_data)

        # Save updated data to CSV
        with open(user_csv_file, "w", newline="", encoding="utf-8") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=data[0].keys())
            writer.writeheader()
            writer.writerows(data)

        return jsonify({"message": "Row updated successfully!"})
    else:
        return jsonify({"message": "Invalid row index."}), 400

@app.route("/delete_data", methods=["POST"])
def delete_data():
    row_indices = request.json.get("indices", [])  # List of row indices to delete

    user_csv_file = os.path.join(UPLOAD_FOLDER, f'scraped_data_{session["user_id"]}.csv')
    if os.path.exists(user_csv_file):
        with open(user_csv_file, "r", encoding="utf-8") as csvfile:
            reader = csv.DictReader(csvfile)
            data = [row for row in reader]
    else:
        data = []

    # Delete rows
    data = [row for i, row in enumerate(data) if i not in row_indices]

    # Save updated data to CSV
    with open(user_csv_file, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=data[0].keys())
        writer.writeheader()
        writer.writerows(data)

    return jsonify({"message": "Rows deleted successfully!"})

@app.route("/group_by", methods=["POST"])
def group_by():
    group_column = request.json.get("column", "locations")  # Column to group by

    user_csv_file = os.path.join(UPLOAD_FOLDER, f'scraped_data_{session["user_id"]}.csv')
    if os.path.exists(user_csv_file):
        with open(user_csv_file, "r", encoding="utf-8") as csvfile:
            reader = csv.DictReader(csvfile)
            data = [row for row in reader]
    else:
        data = []

    # Group data
    grouped_data = {}
    for row in data:
        key = row.get(group_column, "Unknown")
        if key not in grouped_data:
            grouped_data[key] = []
        grouped_data[key].append(row)

    return jsonify(grouped_data)

@app.route("/paginate_data", methods=["POST"])
def paginate_data():
    page = request.json.get("page", 1)  # Page number
    per_page = request.json.get("per_page", 10)  # Rows per page

    user_csv_file = os.path.join(UPLOAD_FOLDER, f'scraped_data_{session["user_id"]}.csv')
    if os.path.exists(user_csv_file):
        with open(user_csv_file, "r", encoding="utf-8") as csvfile:
            reader = csv.DictReader(csvfile)
            data = [row for row in reader]
    else:
        data = []

    # Paginate data
    start = (page - 1) * per_page
    end = start + per_page
    paginated_data = data[start:end]

    return jsonify(paginated_data)


# API to get email status stats for the logged-in user
@app.route("/get_email_stats", methods=["GET"])
def get_email_stats():
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"message": "User not logged in."}), 401

    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT email FROM users WHERE id = %s", (user_id,))
    user = cursor.fetchone()
    if not user:
        return jsonify({"message": "User not found."}), 404

    # Get email status counts
    cursor.execute("SELECT status, COUNT(*) as count FROM email_status WHERE user_email = %s GROUP BY status", (user['email'],))
    status_counts = cursor.fetchall()

    # Get daily email sending count
    cursor.execute("SELECT DATE(timestamp) as date, COUNT(*) as count FROM email_status WHERE user_email = %s GROUP BY DATE(timestamp)", (user['email'],))
    daily_counts = cursor.fetchall()

    # Get feature counts from CSV
    user_csv_file = os.path.join(UPLOAD_FOLDER, f'scraped_data_{user_id}.csv')
    feature_counts = {}
    if os.path.exists(user_csv_file):
        with open(user_csv_file, "r", encoding="utf-8") as csvfile:
            reader = csv.DictReader(csvfile)
            data = [row for row in reader]
            if data:
                for key in data[0].keys():
                    feature_counts[key] = len([row[key] for row in data if row[key]])

    return jsonify({
        "status_counts": status_counts,
        "daily_counts": daily_counts,
        "feature_counts": feature_counts
    })
# Run the app
if __name__ == '__main__':
    app.run(debug=True)