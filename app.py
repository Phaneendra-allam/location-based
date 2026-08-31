from flask import Flask, render_template, request, redirect, url_for, flash, session
import pandas as pd
import os
from datetime import datetime
import hashlib
import geopy.distance
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import geocoder
import base64
import pickle
import re
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = "your_secret_key_here"  # Change this to a secure key

USER_FILE = "users.csv"
MODEL_FILE = "xgb_access_model.pkl"
PHISHING_MODEL_FILE = "phishing.pkl"
UPLOAD_FOLDER = "uploads"

with open(PHISHING_MODEL_FILE, "rb") as f:
    phishing_model = pickle.load(f)

with open(MODEL_FILE, "rb") as f:
    model = pickle.load(f)

os.makedirs(UPLOAD_FOLDER, exist_ok=True)


def encrypt_message_aes(key, message):
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv
    encrypted_message = cipher.encrypt(pad(message.encode(), AES.block_size))
    return base64.b64encode(iv + encrypted_message).decode("utf-8")


def decrypt_message_aes(key, encrypted_message_with_iv):
    encrypted_data = base64.b64decode(encrypted_message_with_iv)
    iv = encrypted_data[:AES.block_size]
    encrypted_message = encrypted_data[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(encrypted_message), AES.block_size).decode("utf-8")


def get_current_location():
    g = geocoder.ip("me")
    return g.latlng


def is_within_offices(current_location, office_locations, radius_km):
    for office in office_locations:
        distance = geopy.distance.distance(current_location, office).km
        if distance <= radius_km:
            return True, office
    return False, None


def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


def init_users_file():
    if not os.path.exists(USER_FILE) or os.stat(USER_FILE).st_size == 0:
        df = pd.DataFrame(
            columns=[
                "username",
                "password",
                "email",
                "signup_date",
                "user_role",
                "department",
                "years_of_service",
                "access_time",
                "access_attempts",
                "last_login_time",
                "login_frequency",
            ]
        )
        df.to_csv(USER_FILE, index=False)


def extract_urls(text):
    url_pattern = re.compile(
        r"(https?://[^\s]+|www\.[^\s]+|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/[^\s]*)"
    )
    return list(set(url_pattern.findall(text)))


def load_users():
    init_users_file()
    try:
        users_df = pd.read_csv(USER_FILE)
        expected_columns = [
            "username",
            "password",
            "email",
            "signup_date",
            "user_role",
            "department",
            "years_of_service",
            "access_time",
            "access_attempts",
            "last_login_time",
            "login_frequency",
        ]
        for col in expected_columns:
            if col not in users_df.columns:
                users_df[col] = pd.Series(
                    dtype=(
                        str
                        if col.endswith("time")
                        else float
                        if col in ["years_of_service", "login_frequency", "access_attempts"]
                        else str
                    )
                )
        return users_df
    except pd.errors.EmptyDataError:
        return pd.DataFrame(
            columns=[
                "username",
                "password",
                "email",
                "signup_date",
                "user_role",
                "department",
                "years_of_service",
                "access_time",
                "access_attempts",
                "last_login_time",
                "login_frequency",
            ]
        )


def save_user(username, password, email, user_role, department, years_of_service):
    users_df = load_users()
    new_user = pd.DataFrame(
        {
            "username": [username],
            "password": [hash_password(password)],
            "email": [email],
            "signup_date": [datetime.now().strftime("%Y-%m-%d %H:%M:%S")],
            "user_role": [user_role],
            "department": [department],
            "years_of_service": [float(years_of_service)],
            "access_time": [""],
            "access_attempts": [0],
            "last_login_time": [""],
            "login_frequency": [0.0],
        }
    )
    users_df = pd.concat([users_df, new_user], ignore_index=True)
    users_df.to_csv(USER_FILE, index=False)


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in {"txt", "csv", "log"}


def update_user_data(username, access_time=None, login_time=None):
    users_df = load_users()
    current_date = datetime.now().date()
    user_idx = users_df[users_df["username"] == username].index[0]

    last_access = users_df.at[user_idx, "access_time"]
    if last_access and not pd.isna(pd.to_datetime(last_access)) and pd.to_datetime(last_access).date() < current_date:
        users_df.at[user_idx, "access_time"] = ""
        users_df.at[user_idx, "access_attempts"] = 0
        users_df.at[user_idx, "login_frequency"] = 0.0

    if access_time:
        if users_df.at[user_idx, "access_time"] and not pd.isna(pd.to_datetime(users_df.at[user_idx, "access_time"])):
            users_df.at[user_idx, "access_attempts"] += 1
        else:
            users_df.at[user_idx, "access_time"] = access_time
            users_df.at[user_idx, "access_attempts"] = 1

    if login_time:
        current_login_date = pd.to_datetime(login_time).date()
        last_login = users_df.at[user_idx, "last_login_time"]

        if last_login and not pd.isna(pd.to_datetime(last_login)):
            last_login_date = pd.to_datetime(last_login).date()
            if current_login_date > last_login_date:
                users_df.at[user_idx, "login_frequency"] = 1.0
            else:
                users_df.at[user_idx, "login_frequency"] += 1.0
        else:
            users_df.at[user_idx, "login_frequency"] = 1.0

        users_df.at[user_idx, "last_login_time"] = login_time

    users_df.to_csv(USER_FILE, index=False)
    return users_df


def verify_user(username, password):
    users_df = load_users()
    hashed_pw = hash_password(password)
    user_match = users_df[(users_df["username"] == username) & (users_df["password"] == hashed_pw)]
    return not user_match.empty


def predict_access(user_data):
    df = pd.DataFrame([user_data])
    df["access_time_hour"] = pd.to_datetime(df["access_time"], errors="coerce").dt.hour.fillna(0)
    df["last_login_time_hour"] = pd.to_datetime(df["last_login_time"], errors="coerce").dt.hour.fillna(0)
    df = df.drop(["access_time", "last_login_time"], axis=1)
    df = pd.get_dummies(df, columns=["user_role", "department"])

    training_features = model.feature_names_in_
    for col in training_features:
        if col not in df.columns:
            df[col] = 0
    df = df[training_features]

    return model.predict(df)[0]


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        if verify_user(username, password):
            session["logged_in"] = True
            session["username"] = username
            session.pop("access_granted", None)
            update_user_data(username, login_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            flash("Logged in successfully!", "success")
            return redirect(url_for("home"))

        flash("Invalid username or password", "error")

    return render_template("login.html")


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]
        user_role = request.form["user_role"]
        department = request.form["department"]
        years_of_service = request.form["years_of_service"]

        users_df = load_users()
        if username in users_df["username"].values:
            flash("Username already exists!", "error")
        elif password != confirm_password:
            flash("Passwords don't match!", "error")
        elif len(password) < 6:
            flash("Password must be at least 6 characters!", "error")
        else:
            save_user(username, password, email, user_role, department, years_of_service)
            flash("Account created successfully! Please login.", "success")
            return redirect(url_for("login"))

    return render_template("signup.html")


@app.route("/home", methods=["GET", "POST"])
def home():
    if not session.get("logged_in"):
        flash("Please login first!", "error")
        return redirect(url_for("login"))

    username = session["username"]
    users_df = load_users()
    user_data = users_df[users_df["username"] == username].iloc[0].to_dict()

    office_locations = [
        (16.5074, 80.6466),
        (28.704060, 77.102493),
        (19.076090, 72.877426),
    ]
    radius_km = 1.0
    key = get_random_bytes(16)
    secret_message = "This is a confidential message."
    encrypted_message = encrypt_message_aes(key, secret_message)
    current_location = None
    access_granted = session.get("access_granted", False)
    matched_office = None
    decrypted_message = None

    if request.method == "POST" and "get_location" in request.form:
        office1 = tuple(map(float, request.form.get("office1").split(",")))
        office2 = tuple(map(float, request.form.get("office2").split(",")))
        office3 = tuple(map(float, request.form.get("office3").split(",")))
        radius_km = float(request.form.get("radius"))
        secret_message = request.form.get("secret_message")

        office_locations = [office1, office2, office3]
        encrypted_message = encrypt_message_aes(key, secret_message)

        current_location = get_current_location()
        access_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        users_df = update_user_data(username, access_time=access_time)
        user_data = users_df[users_df["username"] == username].iloc[0].to_dict()

        access_granted_ml = predict_access(user_data)
        access_granted_geo, matched_office = is_within_offices(current_location, office_locations, radius_km)
        access_granted = access_granted_ml and access_granted_geo

        if access_granted:
            session["access_granted"] = True
            decrypted_message = decrypt_message_aes(key, encrypted_message)
            session["decrypted_message"] = decrypted_message
            flash(f"Access Granted! ML Prediction: Yes, Location: {matched_office}", "success")
            return redirect(url_for("transfer"))

        session.pop("access_granted", None)
        flash("Access Denied! Check ML prediction or location.", "error")

    return render_template(
        "home.html",
        username=username,
        office1=f"{office_locations[0][0]}, {office_locations[0][1]}",
        office2=f"{office_locations[1][0]}, {office_locations[1][1]}",
        office3=f"{office_locations[2][0]}, {office_locations[2][1]}",
        radius=radius_km,
        secret_message=secret_message,
        encrypted_message=encrypted_message,
        current_location=current_location,
        access_granted=access_granted,
        decrypted_message=decrypted_message,
    )


@app.route("/transfer", methods=["GET", "POST"])
def transfer():
    if not session.get("logged_in"):
        flash("Please login first!", "error")
        return redirect(url_for("login"))

    if not session.get("access_granted"):
        flash("Complete access verification first!", "error")
        return redirect(url_for("home"))

    phishing_results = []
    decrypted_message = session.get("decrypted_message")

    if request.method == "POST" and "upload_file" in request.form:
        file = request.files.get("file")

        if file and allowed_file(file.filename):
            content = file.read().decode(errors="ignore")
            urls = extract_urls(content)
            phishing_found = False

            if urls:
                predictions = phishing_model.predict(urls)
                for url, prediction in zip(urls, predictions):
                    status = "PHISHING" if prediction == "bad" else "NO PHISHING DETECTED"
                    phishing_results.append({"url": url, "status": status})
                    if prediction == "bad":
                        phishing_found = True
            else:
                phishing_results.append({"url": "No URLs found in file", "status": "NO PHISHING DETECTED"})

            if phishing_found:
                flash("File not transferred, phishing detected.", "error")
            else:
                file.seek(0)
                safe_name = secure_filename(file.filename)
                file_path = os.path.join(UPLOAD_FOLDER, safe_name)
                file.save(file_path)
                flash("File sent successfully.", "success")
        else:
            flash("Invalid file type!", "error")

    return render_template(
        "transfer.html",
        username=session["username"],
        phishing_results=phishing_results,
        decrypted_message=decrypted_message,
    )


@app.route("/logout")
def logout():
    session.pop("logged_in", None)
    session.pop("username", None)
    session.pop("access_granted", None)
    session.pop("decrypted_message", None)
    flash("Logged out successfully!", "success")
    return redirect(url_for("index"))


if __name__ == "__main__":
    app.run(debug=True)
