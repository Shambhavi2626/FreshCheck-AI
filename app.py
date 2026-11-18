from flask import (
    Flask, render_template, request, jsonify,
    redirect, url_for, session
)

import os
import uuid
import json
import mysql.connector

from datetime import datetime
from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)
from functools import wraps
from collections import Counter

import numpy as np
import cv2
import joblib


# ---------------- FLASK CONFIGURATION ----------------

app = Flask(__name__)

app.secret_key = os.environ.get(
    "SECRET_KEY",
    "freshcheck-ai-change-this-secret-key"
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app.config["UPLOAD_FOLDER"] = os.path.join(
    BASE_DIR, "static", "uploads"
)

app.config["MAX_CONTENT_LENGTH"] = 150 * 1024 * 1024

os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)


# ---------------- MYSQL CONFIGURATION ----------------

DB_HOST = os.environ.get("MYSQL_HOST", "localhost")

DB_CONFIG = {
    "host": DB_HOST,
    "user": os.environ.get("MYSQL_USER", "root"),
    "password": os.environ.get("MYSQL_PASSWORD", ""),
    "database": os.environ.get("MYSQL_DATABASE", "freshcheck_ai"),
    "port": int(os.environ.get("MYSQL_PORT", "3306")),
    "connection_timeout": 20,
}

if DB_HOST not in ("localhost", "127.0.0.1"):

    DB_CONFIG.update({
        "ssl_ca": os.environ.get(
            "MYSQL_SSL_CA",
            "/etc/ssl/certs/ca-certificates.crt"
        ),
        "ssl_verify_cert": True,
        "ssl_verify_identity": True,
    })


# ---------------- DATABASE CONNECTION ----------------

class Database:

    def __enter__(self):

        self.connection = mysql.connector.connect(**DB_CONFIG)
        self.cursors = []

        return self

    def execute(self, query, params=()):

        cursor = self.connection.cursor(dictionary=True)
        self.cursors.append(cursor)

        cursor.execute(query, params)

        return cursor

    def __exit__(self, exc_type, exc_value, traceback):

        try:

            if exc_type is None:
                self.connection.commit()

            else:
                self.connection.rollback()

        finally:

            for cursor in self.cursors:
                cursor.close()

            self.connection.close()


def get_db():
    return Database()


# ---------------- CREATE DATABASE TABLES ----------------

def init_db():

    with get_db() as conn:

        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                name VARCHAR(100) NOT NULL,
                email VARCHAR(150) NOT NULL UNIQUE,
                password_hash VARCHAR(255) NOT NULL,
                created_at VARCHAR(30) NOT NULL
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                payload LONGTEXT,
                created_at VARCHAR(30),
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS login_events (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                logged_in_at DATETIME NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)

        columns = conn.execute(
            """
            SELECT COLUMN_NAME
            FROM information_schema.COLUMNS
            WHERE TABLE_SCHEMA = %s
            AND TABLE_NAME = 'scans'
            """,
            (DB_CONFIG["database"],)
        ).fetchall()

        existing = {
            row["COLUMN_NAME"] for row in columns
        }

        if "payload" not in existing:

            conn.execute(
                "ALTER TABLE scans ADD COLUMN payload LONGTEXT NULL"
            )

        if "created_at" not in existing:

            conn.execute(
                "ALTER TABLE scans ADD COLUMN created_at VARCHAR(30) NULL"
            )

        conn.execute(
            "UPDATE scans SET payload = %s WHERE payload IS NULL",
            (json.dumps({}),)
        )

        conn.execute(
            "UPDATE scans SET created_at = %s WHERE created_at IS NULL",
            (datetime.now().isoformat(timespec="seconds"),)
        )


# ---------------- LOGIN REQUIRED ----------------

def login_required(fn):

    @wraps(fn)
    def wrapper(*args, **kwargs):

        if "user_id" not in session:

            # API requests must receive JSON, not HTML

            if request.path.startswith("/api/"):

                return jsonify({
                    "success": False,
                    "error": "Session expired. Please login again."
                }), 401

            return redirect(url_for("login"))

        return fn(*args, **kwargs)

    return wrapper


# ---------------- USER REGISTRATION ----------------

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        name = request.form.get("name", "").strip()

        email = request.form.get("email", "").strip().lower()

        password = request.form.get("password", "")

        if not name or not email or len(password) < 6:

            return render_template(
                "register.html",
                error="Enter your name, valid email and password (at least 6 characters)."
            )

        try:

            with get_db() as conn:

                cur = conn.execute(
                    """
                    INSERT INTO users
                    (name, email, password_hash, created_at)
                    VALUES (%s, %s, %s, %s)
                    """,
                    (
                        name,
                        email,
                        generate_password_hash(password),
                        datetime.now()
                    )
                )

                new_user_id = cur.lastrowid

            session.clear()

            session["user_id"] = new_user_id

            session["user_name"] = name

            return redirect(url_for("index"))

        except mysql.connector.IntegrityError:

            return render_template(
                "register.html",
                error="This email is already registered. Please log in."
            )

    return render_template("register.html")


# ---------------- USER LOGIN ----------------

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        email = request.form.get("email", "").strip().lower()

        password = request.form.get("password", "")

        with get_db() as conn:

            user = conn.execute(
                "SELECT * FROM users WHERE email=%s",
                (email,)
            ).fetchone()

        if user and check_password_hash(
            user["password_hash"], password
        ):

            with get_db() as conn:

                conn.execute(
                    """
                    INSERT INTO login_events
                    (user_id, logged_in_at)
                    VALUES (%s, %s)
                    """,
                    (user["id"], datetime.now())
                )

            session.clear()

            session["user_id"] = user["id"]

            session["user_name"] = user["name"]

            return redirect(url_for("index"))

        return render_template(
            "login.html",
            error="Incorrect email or password."
        )

    return render_template("login.html")


# ---------------- USER LOGOUT ----------------

@app.post("/logout")
@login_required
def logout():

    session.clear()

    return redirect(url_for("login"))


# ---------------- AI MODEL ----------------

MODEL_PATH = os.path.join(
    BASE_DIR,
    "model",
    "freshness_model.joblib"
)

model = joblib.load(MODEL_PATH)

LABELS = {
    0: "Fresh",
    1: "Ripe",
    2: "Spoiled"
}


# ---------------- IMAGE FEATURE EXTRACTION ----------------

def extract_features(img):

    img = cv2.resize(img, (224, 224))

    rgb = cv2.cvtColor(img, cv2.COLOR_BGR2RGB)

    hsv = cv2.cvtColor(img, cv2.COLOR_BGR2HSV)

    mean_rgb = rgb.mean(axis=(0, 1))

    sat = float(hsv[:, :, 1].mean())

    val = float(hsv[:, :, 2].mean())

    brown_mask = (
        (hsv[:, :, 0] >= 5) &
        (hsv[:, :, 0] <= 25) &
        (hsv[:, :, 1] >= 60) &
        (hsv[:, :, 2] >= 40) &
        (hsv[:, :, 2] <= 190)
    )

    dark_mask = hsv[:, :, 2] < 75

    gray = cv2.cvtColor(
        img,
        cv2.COLOR_BGR2GRAY
    )

    texture = float(gray.std())

    return np.r_[
        mean_rgb,
        sat,
        val,
        brown_mask.mean(),
        dark_mask.mean(),
        texture
    ].reshape(1, -1)


# ---------------- AI IMAGE PREDICTION ----------------

def predict_image(path):

    img = cv2.imread(path)

    if img is None:

        raise ValueError(
            "Could not read one of the uploaded images."
        )

    features = extract_features(img)

    pred = int(model.predict(features)[0])

    probabilities = model.predict_proba(features)[0]

    confidence = float(probabilities[pred] * 100)

    quality = {
        "Fresh": 92,
        "Ripe": 72,
        "Spoiled": 28
    }[LABELS[pred]]

    quality = int(
        max(
            5,
            min(99, quality + (confidence - 75) * 0.08)
        )
    )

    return LABELS[pred], quality, round(confidence, 1)


# ---------------- VIDEO ANALYSIS ----------------

def analyze_video(video_path, max_frames=5):

    cap = cv2.VideoCapture(video_path)

    if not cap.isOpened():

        raise ValueError(
            "Could not open the uploaded video. Please use MP4, MOV or AVI."
        )

    total = int(
        cap.get(cv2.CAP_PROP_FRAME_COUNT) or 0
    )

    fps = cap.get(cv2.CAP_PROP_FPS) or 0

    duration = (total / fps) if fps > 0 else 0

    if total <= 0:

        cap.release()

        raise ValueError(
            "The uploaded video has no readable frames."
        )

    positions = np.linspace(
        0,
        max(total - 1, 0),
        min(max_frames, total),
        dtype=int
    )

    results = []

    saved_frames = []

    for index, frame_no in enumerate(positions):

        cap.set(
            cv2.CAP_PROP_POS_FRAMES,
            int(frame_no)
        )

        ok, frame = cap.read()

        if not ok:
            continue

        frame_name = (
            f"{uuid.uuid4().hex}_frame{index + 1}.jpg"
        )

        frame_path = os.path.join(
            app.config["UPLOAD_FOLDER"],
            frame_name
        )

        if cv2.imwrite(frame_path, frame):

            saved_frames.append(
                f"/static/uploads/{frame_name}"
            )

            results.append(
                predict_image(frame_path)
            )

    cap.release()

    if not results:

        raise ValueError(
            "No usable frames could be extracted from this video."
        )

    return results, saved_frames, round(duration, 1)


# ---------------- COMBINE PREDICTIONS ----------------

def combine_predictions(results):

    condition = Counter(
        item[0] for item in results
    ).most_common(1)[0][0]

    score = round(
        sum(item[1] for item in results) / len(results)
    )

    confidence = round(
        sum(item[2] for item in results) / len(results),
        1
    )

    return condition, score, confidence


# ---------------- HOME PAGE ----------------

@app.route("/")
@login_required
def index():

    return render_template("index.html")


# ---------------- DASHBOARD ----------------

@app.route("/dashboard")
@login_required
def dashboard():

    return render_template("dashboard.html")


# ---------------- FOOD SCAN API ----------------

@app.post("/api/scan")
@login_required
def scan():

    uploaded_images = request.files.getlist("images")

    if not uploaded_images or not any(
        f and f.filename for f in uploaded_images
    ):

        single = request.files.get("image")

        uploaded_images = (
            [single] if single and single.filename else []
        )

    video = request.files.get("video")

    has_video = bool(
        video and video.filename
    )

    if not uploaded_images and not has_video:

        return jsonify({
            "error": "Upload up to four side photos, a video, or both."
        }), 400

    if len(uploaded_images) > 4:

        return jsonify({
            "error": "Please upload a maximum of four side photos."
        }), 400

    saved_images = []

    results = []

    selected_sides = request.form.getlist("image_sides")

    try:

        for side_index, image in enumerate(uploaded_images):

            if not image or not image.filename:
                continue

            ext = os.path.splitext(
                image.filename
            )[1].lower()

            if ext not in {
                ".jpg", ".jpeg", ".png",
                ".webp", ".bmp"
            }:

                return jsonify({
                    "error": "Photo formats supported: JPG, JPEG, PNG, WEBP, BMP."
                }), 400

            filename = f"{uuid.uuid4().hex}{ext}"

            path = os.path.join(
                app.config["UPLOAD_FOLDER"],
                filename
            )

            image.save(path)

            results.append(
                predict_image(path)
            )

            side_label = (
                selected_sides[side_index]
                if side_index < len(selected_sides)
                else ["Front", "Back", "Left", "Right"][
                    min(side_index, 3)
                ]
            )

            saved_images.append({
                "side": side_label,
                "url": f"/static/uploads/{filename}"
            })

        video_frames = []

        duration = None

        if has_video:

            vext = os.path.splitext(
                video.filename
            )[1].lower()

            if vext not in {
                ".mp4", ".mov", ".avi",
                ".mkv", ".webm"
            }:

                return jsonify({
                    "error": "Video formats supported: MP4, MOV, AVI, MKV, WEBM."
                }), 400

            video_name = (
                f"{uuid.uuid4().hex}{vext}"
            )

            video_path = os.path.join(
                app.config["UPLOAD_FOLDER"],
                video_name
            )

            video.save(video_path)

            video_results, video_frames, duration = (
                analyze_video(video_path)
            )

            results.extend(video_results)

        if not results:

            return jsonify({
                "error": "No valid photo or video frames could be analyzed."
            }), 400

        condition, quality, confidence = (
            combine_predictions(results)
        )

    except (ValueError, cv2.error) as exc:

        return jsonify({
            "error": str(exc)
        }), 400

    # ---------------- GPS LOCATION ----------------

    latitude = request.form.get("latitude") or None

    longitude = request.form.get("longitude") or None

    address_text = request.form.get(
        "address", ""
    ).strip()

    # ---------------- FOOD RECOMMENDATION ----------------

    recommendation = {
        "Fresh": "Looks in good condition. Store in a clean place at the appropriate temperature.",

        "Ripe": "Use soon and store appropriately to slow further ripening.",

        "Spoiled": "Do not rely on this visual estimate alone. If there are spoilage signs, avoid eating it."
    }[condition]

    # ---------------- SCAN RECORD ----------------

    scan_record = {

        "id": None,

        "user_id": session["user_id"],

        "food_type": request.form.get(
            "food_type", "Food"
        ).strip()[:60] or "Food",

        "images": saved_images,

        "image": (
            saved_images[0]["url"]
            if saved_images
            else (
                video_frames[0]
                if video_frames else ""
            )
        ),

        "video_frames": video_frames,

        "video_duration_seconds": duration,

        "analyzed_views": len(results),

        "condition": condition,

        "quality_score": quality,

        "confidence": confidence,

        "recommendation": recommendation,

        "latitude": latitude,

        "longitude": longitude,

        "address": address_text,

        "date_time": datetime.now().strftime(
            "%d-%m-%Y %I:%M %p"
        )
    }

    # ---------------- SAVE SCAN IN MYSQL ----------------

    with get_db() as conn:

        cur = conn.execute(
            """
            INSERT INTO scans
            (user_id, payload, created_at)
            VALUES (%s, %s, %s)
            """,
            (
                session["user_id"],
                json.dumps(scan_record),
                datetime.now().isoformat(timespec="seconds")
            )
        )

        scan_record["id"] = cur.lastrowid

        conn.execute(
            """
            UPDATE scans
            SET payload=%s
            WHERE id=%s
            """,
            (
                json.dumps(scan_record),
                scan_record["id"]
            )
        )

    return jsonify(scan_record)


# ---------------- USER SCAN HISTORY API ----------------

@app.get("/api/scans")
@login_required
def scans():

    with get_db() as conn:

        rows = conn.execute(
            """
            SELECT payload
            FROM scans
            WHERE user_id=%s
            ORDER BY id DESC
            """,
            (session["user_id"],)
        ).fetchall()

    return jsonify([
        json.loads(row["payload"])
        for row in rows
    ])


# ---------------- RESULT PAGE ----------------

@app.get("/result/<int:scan_id>")
@login_required
def result_page(scan_id):

    with get_db() as conn:

        row = conn.execute(
            """
            SELECT payload
            FROM scans
            WHERE id=%s AND user_id=%s
            """,
            (
                scan_id,
                session["user_id"]
            )
        ).fetchone()

    if not row:

        return redirect(
            url_for("dashboard")
        )

    return render_template(
        "result.html",
        scan=json.loads(row["payload"])
    )


# ---------------- ADMIN / DASHBOARD STATISTICS API ----------------

@app.get("/api/admin/stats")
@login_required
def admin_stats():

    with get_db() as conn:

        users = conn.execute(
            """
            SELECT COUNT(*) AS total
            FROM users
            """
        ).fetchone()["total"]

        logins = conn.execute(
            """
            SELECT COUNT(*) AS total
            FROM login_events
            """
        ).fetchone()["total"]

        total_scans = conn.execute(
            """
            SELECT COUNT(*) AS total
            FROM scans
            """
        ).fetchone()["total"]

        rows = conn.execute(
            """
            SELECT payload
            FROM scans
            """
        ).fetchall()

    total_images = 0

    total_video_frames = 0

    for row in rows:

        data = json.loads(
            row["payload"]
        )

        total_images += len(
            data.get("images", [])
        )

        total_video_frames += len(
            data.get("video_frames", [])
        )

    return jsonify({

        "registered_users": users,

        "total_logins": logins,

        "total_scans": total_scans,

        "images_scanned": total_images,

        "video_frames_scanned": total_video_frames

    })


# ---------------- PROTECT PRIVATE PAGES ----------------

@app.before_request
def protect_private_pages():

    public = {
        "login",
        "register",
        "static"
    }

    if (
        request.endpoint
        and request.endpoint not in public
        and "user_id" not in session
    ):

        # IMPORTANT:
        # Return JSON for API requests.
        # Do not redirect API requests to the login HTML page.

        if request.path.startswith("/api/"):

            return jsonify({
                "success": False,
                "error": "Session expired. Please login again."
            }), 401

        return redirect(
            url_for("login")
        )


# ---------------- API ERROR HANDLERS ----------------

@app.errorhandler(404)
def page_not_found(error):

    if request.path.startswith("/api/"):

        return jsonify({
            "success": False,
            "error": "API endpoint not found."
        }), 404

    return "Page not found.", 404


@app.errorhandler(500)
def internal_server_error(error):

    if request.path.startswith("/api/"):

        return jsonify({
            "success": False,
            "error": "Internal server error. Please try again."
        }), 500

    return "Internal server error. Please try again.", 500


# ---------------- FILE SIZE ERROR ----------------

@app.errorhandler(413)
def too_large(error):

    return jsonify({

        "success": False,

        "error": "Upload is too large. Maximum combined upload size is 150 MB."

    }), 413


# ---------------- INITIALIZE DATABASE ----------------

init_db()


# ---------------- RUN APPLICATION ----------------

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", "5000")),
        debug=False
    )
