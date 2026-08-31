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

# Use an environment variable in production.
app.secret_key = os.environ.get("SECRET_KEY", "change-this-secret-key")


# --------------------------------------------------
# BASE DIRECTORY
# --------------------------------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

USER_FILE = os.path.join(BASE_DIR, "users.csv")
MODEL_FILE = os.path.join(BASE_DIR, "xgb_access_model.pkl")
PHISHING_MODEL_FILE = os.path.join(BASE_DIR, "phishing.pkl")

# Vercel's filesystem is temporary.
# /tmp is the writable location for serverless functions.
UPLOAD_FOLDER = "/tmp/uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


# --------------------------------------------------
# LAZY MODEL LOADING
# --------------------------------------------------

_model = None
_phishing_model = None


def get_access_model():
    global _model

    if _model is None:
        if not os.path.exists(MODEL_FILE):
            raise FileNotFoundError(
                f"Access model not found: {MODEL_FILE}"
            )

        with open(MODEL_FILE, "rb") as f:
            _model = pickle.load(f)

    return _model


def get_phishing_model():
    global _phishing_model

    if _phishing_model is None:
        if not os.path.exists(PHISHING_MODEL_FILE):
            raise FileNotFoundError(
                f"Phishing model not found: {PHISHING_MODEL_FILE}"
            )

        with open(PHISHING_MODEL_FILE, "rb") as f:
            _phishing_model = pickle.load(f)

    return _phishing_model


# --------------------------------------------------
# AES ENCRYPTION
# --------------------------------------------------

def encrypt_message_aes(key, message):
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv

    encrypted_message = cipher.encrypt(
        pad(message.encode(), AES.block_size)
    )

    return base64.b64encode(
        iv + encrypted_message
    ).decode("utf-8")


def decrypt_message_aes(key, encrypted_message_with_iv):
    encrypted_data = base64.b64decode(
        encrypted_message_with_iv
    )

    iv = encrypted_data[:AES.block_size]
    encrypted_message = encrypted_data[AES.block_size:]

    cipher = AES.new(
        key,
        AES.MODE_CBC,
        iv
    )

    return unpad(
        cipher.decrypt(encrypted_message),
        AES.block_size
    ).decode("utf-8")


# --------------------------------------------------
# LOCATION
# --------------------------------------------------

def get_current_location():
    try:
        g = geocoder.ip("me")

        if g.ok and g.latlng:
            return g.latlng

    except Exception as e:
        print(f"Location lookup failed: {e}")

    return None


def is_within_offices(
    current_location,
    office_locations,
    radius_km
):
    if not current_location:
        return False, None

    for office in office_locations:
        try:
            distance = geopy.distance.distance(
                current_location,
                office
            ).km

            if distance <= radius_km:
                return True, office

        except Exception as e:
            print(f"Distance calculation failed: {e}")

    return False, None


# --------------------------------------------------
# PASSWORD
# --------------------------------------------------

def hash_password(password):
    return hashlib.sha256(
        password.encode()
    ).hexdigest()


# --------------------------------------------------
# USERS
# --------------------------------------------------

USER_COLUMNS = [
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


def init_users_file():
    if (
        not os.path.exists(USER_FILE)
        or os.stat(USER_FILE).st_size == 0
    ):
        df = pd.DataFrame(
            columns=USER_COLUMNS
        )

        df.to_csv(
            USER_FILE,
            index=False
        )


def load_users():
    init_users_file()

    try:
        users_df = pd.read_csv(USER_FILE)

        for col in USER_COLUMNS:
            if col not in users_df.columns:
                users_df[col] = ""

        return users_df

    except pd.errors.EmptyDataError:
        return pd.DataFrame(
            columns=USER_COLUMNS
        )


def save_user(
    username,
    password,
    email,
    user_role,
    department,
    years_of_service
):
    users_df = load_users()

    new_user = pd.DataFrame({
        "username": [username],
        "password": [hash_password(password)],
        "email": [email],
        "signup_date": [
            datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            )
        ],
        "user_role": [user_role],
        "department": [department],
        "years_of_service": [
            float(years_of_service)
        ],
        "access_time": [""],
        "access_attempts": [0],
        "last_login_time": [""],
        "login_frequency": [0.0],
    })

    users_df = pd.concat(
        [users_df, new_user],
        ignore_index=True
    )

    users_df.to_csv(
        USER_FILE,
        index=False
    )


# --------------------------------------------------
# USER ACTIVITY
# --------------------------------------------------

def update_user_data(
    username,
    access_time=None,
    login_time=None
):
    users_df = load_users()

    matches = users_df[
        users_df["username"] == username
    ]

    if matches.empty:
        return users_df

    user_idx = matches.index[0]

    last_access = users_df.at[
        user_idx,
        "access_time"
    ]

    try:
        if (
            last_access
            and not pd.isna(
                pd.to_datetime(last_access)
            )
        ):
            if (
                pd.to_datetime(
                    last_access
                ).date()
                < datetime.now().date()
            ):
                users_df.at[
                    user_idx,
                    "access_time"
                ] = ""

                users_df.at[
                    user_idx,
                    "access_attempts"
                ] = 0

                users_df.at[
                    user_idx,
                    "login_frequency"
                ] = 0.0

    except Exception:
        pass

    if access_time:
        current_access = users_df.at[
            user_idx,
            "access_time"
        ]

        if current_access:
            try:
                users_df.at[
                    user_idx,
                    "access_attempts"
                ] = int(
                    users_df.at[
                        user_idx,
                        "access_attempts"
                    ]
                ) + 1
            except Exception:
                users_df.at[
                    user_idx,
                    "access_attempts"
                ] = 1
        else:
            users_df.at[
                user_idx,
                "access_time"
            ] = access_time

            users_df.at[
                user_idx,
                "access_attempts"
            ] = 1

    if login_time:
        try:
            current_login_date = pd.to_datetime(
                login_time
            ).date()

            last_login = users_df.at[
                user_idx,
                "last_login_time"
            ]

            if last_login:
                last_login_date = pd.to_datetime(
                    last_login
                ).date()

                if current_login_date > last_login_date:
                    users_df.at[
                        user_idx,
                        "login_frequency"
                    ] = 1.0
                else:
                    users_df.at[
                        user_idx,
                        "login_frequency"
                    ] = float(
                        users_df.at[
                            user_idx,
                            "login_frequency"
                        ]
                    ) + 1.0

            else:
                users_df.at[
                    user_idx,
                    "login_frequency"
                ] = 1.0

            users_df.at[
                user_idx,
                "last_login_time"
            ] = login_time

        except Exception as e:
            print(
                f"Login tracking failed: {e}"
            )

    try:
        users_df.to_csv(
            USER_FILE,
            index=False
        )
    except Exception as e:
        print(
            f"Could not save users.csv: {e}"
        )

    return users_df


def verify_user(username, password):
    users_df = load_users()

    hashed_pw = hash_password(
        password
    )

    user_match = users_df[
        (users_df["username"] == username)
        &
        (users_df["password"] == hashed_pw)
    ]

    return not user_match.empty


# --------------------------------------------------
# PHISHING
# --------------------------------------------------

def extract_urls(text):
    url_pattern = re.compile(
        r"(https?://[^\s]+|www\.[^\s]+|"
        r"[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/[^\s]*)"
    )

    return list(
        set(
            url_pattern.findall(text)
        )
    )


def allowed_file(filename):
    return (
        "." in filename
        and filename.rsplit(
            ".",
            1
        )[1].lower()
        in {"txt", "csv", "log"}
    )


# --------------------------------------------------
# ML ACCESS PREDICTION
# --------------------------------------------------

def predict_access(user_data):

    model = get_access_model()

    df = pd.DataFrame(
        [user_data]
    )

    df["access_time_hour"] = (
        pd.to_datetime(
            df["access_time"],
            errors="coerce"
        )
        .dt.hour
        .fillna(0)
    )

    df["last_login_time_hour"] = (
        pd.to_datetime(
            df["last_login_time"],
            errors="coerce"
        )
        .dt.hour
        .fillna(0)
    )

    df = df.drop(
        [
            "access_time",
            "last_login_time"
        ],
        axis=1
    )

    df = pd.get_dummies(
        df,
        columns=[
            "user_role",
            "department"
        ]
    )

    training_features = (
        model.feature_names_in_
    )

    for col in training_features:
        if col not in df.columns:
            df[col] = 0

    df = df[
        training_features
    ]

    return model.predict(df)[0]


# --------------------------------------------------
# HOME
# --------------------------------------------------

@app.route("/")
def index():
    return render_template(
        "index.html"
    )


# --------------------------------------------------
# LOGIN
# --------------------------------------------------

@app.route(
    "/login",
    methods=["GET", "POST"]
)
def login():

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        if verify_user(
            username,
            password
        ):
            session["logged_in"] = True
            session["username"] = username

            session.pop(
                "access_granted",
                None
            )

            update_user_data(
                username,
                login_time=datetime.now().strftime(
                    "%Y-%m-%d %H:%M:%S"
                )
            )

            flash(
                "Logged in successfully!",
                "success"
            )

            return redirect(
                url_for("home")
            )

        flash(
            "Invalid username or password",
            "error"
        )

    return render_template(
        "login.html"
    )


# --------------------------------------------------
# SIGNUP
# --------------------------------------------------

@app.route(
    "/signup",
    methods=["GET", "POST"]
)
def signup():

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        email = request.form.get(
            "email",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        confirm_password = request.form.get(
            "confirm_password",
            ""
        )

        user_role = request.form.get(
            "user_role",
            ""
        )

        department = request.form.get(
            "department",
            ""
        )

        years_of_service = request.form.get(
            "years_of_service",
            "0"
        )

        users_df = load_users()

        if username in users_df[
            "username"
        ].values:

            flash(
                "Username already exists!",
                "error"
            )

        elif password != confirm_password:

            flash(
                "Passwords don't match!",
                "error"
            )

        elif len(password) < 6:

            flash(
                "Password must be at least 6 characters!",
                "error"
            )

        else:

            try:

                save_user(
                    username,
                    password,
                    email,
                    user_role,
                    department,
                    years_of_service
                )

                flash(
                    "Account created successfully! Please login.",
                    "success"
                )

                return redirect(
                    url_for("login")
                )

            except Exception as e:

                print(
                    f"Signup error: {e}"
                )

                flash(
                    "Could not create account.",
                    "error"
                )

    return render_template(
        "signup.html"
    )


# --------------------------------------------------
# LOCATION / ACCESS
# --------------------------------------------------

@app.route(
    "/home",
    methods=["GET", "POST"]
)
def home():

    if not session.get(
        "logged_in"
    ):

        flash(
            "Please login first!",
            "error"
        )

        return redirect(
            url_for("login")
        )

    username = session[
        "username"
    ]

    users_df = load_users()

    user_rows = users_df[
        users_df["username"] == username
    ]

    if user_rows.empty:

        session.clear()

        flash(
            "User account not found.",
            "error"
        )

        return redirect(
            url_for("login")
        )

    user_data = (
        user_rows
        .iloc[0]
        .to_dict()
    )

    office_locations = [
        (16.5074, 80.6466),
        (28.704060, 77.102493),
        (19.076090, 72.877426),
    ]

    radius_km = 1.0

    key = get_random_bytes(16)

    secret_message = (
        "This is a confidential message."
    )

    encrypted_message = (
        encrypt_message_aes(
            key,
            secret_message
        )
    )

    current_location = None

    access_granted = session.get(
        "access_granted",
        False
    )

    matched_office = None
    decrypted_message = None

    if (
        request.method == "POST"
        and "get_location" in request.form
    ):

        try:

            office1 = tuple(
                map(
                    float,
                    request.form.get(
                        "office1"
                    ).split(",")
                )
            )

            office2 = tuple(
                map(
                    float,
                    request.form.get(
                        "office2"
                    ).split(",")
                )
            )

            office3 = tuple(
                map(
                    float,
                    request.form.get(
                        "office3"
                    ).split(",")
                )
            )

            radius_km = float(
                request.form.get(
                    "radius"
                )
            )

            secret_message = (
                request.form.get(
                    "secret_message"
                )
                or
                "This is a confidential message."
            )

            office_locations = [
                office1,
                office2,
                office3
            ]

            encrypted_message = (
                encrypt_message_aes(
                    key,
                    secret_message
                )
            )

            current_location = (
                get_current_location()
            )

            if not current_location:

                flash(
                    "Could not determine your location. Please try again.",
                    "error"
                )

            else:

                access_time = (
                    datetime.now().strftime(
                        "%Y-%m-%d %H:%M:%S"
                    )
                )

                users_df = update_user_data(
                    username,
                    access_time=access_time
                )

                user_rows = users_df[
                    users_df["username"] == username
                ]

                if not user_rows.empty:

                    user_data = (
                        user_rows
                        .iloc[0]
                        .to_dict()
                    )

                    try:
                        access_granted_ml = bool(
                            predict_access(
                                user_data
                            )
                        )
                    except Exception as e:

                        print(
                            f"ML prediction error: {e}"
                        )

                        access_granted_ml = False

                    access_granted_geo, matched_office = (
                        is_within_offices(
                            current_location,
                            office_locations,
                            radius_km
                        )
                    )

                    access_granted = (
                        access_granted_ml
                        and access_granted_geo
                    )

                    if access_granted:

                        session[
                            "access_granted"
                        ] = True

                        decrypted_message = (
                            decrypt_message_aes(
                                key,
                                encrypted_message
                            )
                        )

                        session[
                            "decrypted_message"
                        ] = decrypted_message

                        flash(
                            f"Access Granted! ML Prediction: Yes, Location: {matched_office}",
                            "success"
                        )

                        return redirect(
                            url_for("transfer")
                        )

                    session.pop(
                        "access_granted",
                        None
                    )

                    flash(
                        "Access Denied! Check ML prediction or location.",
                        "error"
                    )

        except Exception as e:

            print(
                f"Location verification error: {e}"
            )

            flash(
                "Location verification failed. Please check your inputs and try again.",
                "error"
            )

    return render_template(
        "home.html",
        username=username,
        office1=(
            f"{office_locations[0][0]}, "
            f"{office_locations[0][1]}"
        ),
        office2=(
            f"{office_locations[1][0]}, "
            f"{office_locations[1][1]}"
        ),
        office3=(
            f"{office_locations[2][0]}, "
            f"{office_locations[2][1]}"
        ),
        radius=radius_km,
        secret_message=secret_message,
        encrypted_message=encrypted_message,
        current_location=current_location,
        access_granted=access_granted,
        decrypted_message=decrypted_message,
    )


# --------------------------------------------------
# FILE TRANSFER / PHISHING
# --------------------------------------------------

@app.route(
    "/transfer",
    methods=["GET", "POST"]
)
def transfer():

    if not session.get(
        "logged_in"
    ):

        flash(
            "Please login first!",
            "error"
        )

        return redirect(
            url_for("login")
        )

    if not session.get(
        "access_granted"
    ):

        flash(
            "Complete access verification first!",
            "error"
        )

        return redirect(
            url_for("home")
        )

    phishing_results = []

    decrypted_message = session.get(
        "decrypted_message"
    )

    if (
        request.method == "POST"
        and "upload_file" in request.form
    ):

        file = request.files.get(
            "file"
        )

        if (
            file
            and allowed_file(
                file.filename
            )
        ):

            try:

                content = file.read().decode(
                    errors="ignore"
                )

                urls = extract_urls(
                    content
                )

                phishing_found = False

                if urls:

                    phishing_model = (
                        get_phishing_model()
                    )

                    predictions = (
                        phishing_model.predict(
                            urls
                        )
                    )

                    for url, prediction in zip(
                        urls,
                        predictions
                    ):

                        status = (
                            "PHISHING"
                            if prediction == "bad"
                            else "NO PHISHING DETECTED"
                        )

                        phishing_results.append({
                            "url": url,
                            "status": status
                        })

                        if prediction == "bad":
                            phishing_found = True

                else:

                    phishing_results.append({
                        "url": "No URLs found in file",
                        "status": "NO PHISHING DETECTED"
                    })

                if phishing_found:

                    flash(
                        "File not transferred, phishing detected.",
                        "error"
                    )

                else:

                    file.seek(0)

                    safe_name = secure_filename(
                        file.filename
                    )

                    file_path = os.path.join(
                        UPLOAD_FOLDER,
                        safe_name
                    )

                    file.save(
                        file_path
                    )

                    flash(
                        "File sent successfully.",
                        "success"
                    )

            except Exception as e:

                print(
                    f"File processing error: {e}"
                )

                flash(
                    "Could not process the uploaded file.",
                    "error"
                )

        else:

            flash(
                "Invalid file type!",
                "error"
            )

    return render_template(
        "transfer.html",
        username=session[
            "username"
        ],
        phishing_results=phishing_results,
        decrypted_message=decrypted_message,
    )


# --------------------------------------------------
# LOGOUT
# --------------------------------------------------

@app.route("/logout")
def logout():

    session.pop(
        "logged_in",
        None
    )

    session.pop(
        "username",
        None
    )

    session.pop(
        "access_granted",
        None
    )

    session.pop(
        "decrypted_message",
        None
    )

    flash(
        "Logged out successfully!",
        "success"
    )

    return redirect(
        url_for("index")
    )


# --------------------------------------------------
# VERCEL ENTRY POINT
# --------------------------------------------------

# Vercel imports the Flask application
# from this module.


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(
            os.environ.get(
                "PORT",
                5000
            )
        ),
        debug=False
    )
