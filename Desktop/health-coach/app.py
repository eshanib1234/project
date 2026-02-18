from flask import Flask, render_template, request, jsonify, redirect, session
import sqlite3
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "supersecretkey"  # Change in production

# -----------------------------------
# DATABASE INITIALIZATION
# -----------------------------------
def init_db():
    conn = sqlite3.connect("health.db")
    cursor = conn.cursor()

    # Users table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        role TEXT DEFAULT 'user'
    )
    """)

    # Health records table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS records (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        bmi REAL,
        heart_rate REAL,
        sleep REAL,
        bp REAL,
        risk_score INTEGER,
        risk_level TEXT,
        recommendation TEXT,
        timestamp TEXT
    )
    """)

    conn.commit()
    conn.close()

init_db()

# -----------------------------------
# AUTH ROUTES
# -----------------------------------

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = generate_password_hash(request.form["password"])

        conn = sqlite3.connect("health.db")
        cursor = conn.cursor()

        # First user becomes admin
        cursor.execute("SELECT COUNT(*) FROM users")
        user_count = cursor.fetchone()[0]
        role = "admin" if user_count == 0 else "user"

        try:
            cursor.execute(
                "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                (username, password, role)
            )
            conn.commit()
        except sqlite3.IntegrityError:
            conn.close()
            return "Username already exists!"

        conn.close()
        return redirect("/login")

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        conn = sqlite3.connect("health.db")
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()

        if user and check_password_hash(user[2], password):
            session["user_id"] = user[0]
            session["username"] = user[1]
            session["role"] = user[3]

            if user[3] == "admin":
                return redirect("/admin")

            return redirect("/")

        return "Invalid credentials!"

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


# -----------------------------------
# USER DASHBOARD
# -----------------------------------

@app.route("/")
def home():
    if "user_id" not in session:
        return redirect("/login")
    return render_template("index.html", username=session["username"])


@app.route("/analyze", methods=["POST"])
def analyze():
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.json

    bmi = float(data["bmi"])
    heart_rate = float(data["heart_rate"])
    sleep = float(data["sleep"])
    bp = float(data["bp"])

    score = 0

    # Rule-based scoring engine
    if bmi > 30:
        score += 2
    elif bmi > 25:
        score += 1

    if heart_rate > 100:
        score += 2

    if sleep < 6:
        score += 2

    if bp > 140:
        score += 2

    # Risk classification
    if score <= 2:
        level = "Low Risk"
        recommendation = "Maintain healthy lifestyle. Continue balanced diet and regular exercise."
    elif score <= 5:
        level = "Moderate Risk"
        recommendation = "Improve diet, increase physical activity, and monitor vitals regularly."
    else:
        level = "High Risk"
        recommendation = "Consult a doctor immediately and monitor health indicators daily."

    # Save record
    conn = sqlite3.connect("health.db")
    cursor = conn.cursor()

    cursor.execute("""
    INSERT INTO records
    (user_id, bmi, heart_rate, sleep, bp, risk_score, risk_level, recommendation, timestamp)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        session["user_id"],
        bmi,
        heart_rate,
        sleep,
        bp,
        score,
        level,
        recommendation,
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))

    conn.commit()
    conn.close()

    return jsonify({
        "risk_score": score,
        "risk_level": level,
        "recommendation": recommendation
    })


@app.route("/records")
def records():
    if "user_id" not in session:
        return redirect("/login")

    conn = sqlite3.connect("health.db")
    cursor = conn.cursor()

    cursor.execute("""
    SELECT bmi, heart_rate, sleep, bp, risk_score, risk_level, timestamp
    FROM records
    WHERE user_id = ?
    ORDER BY id DESC
    """, (session["user_id"],))

    rows = cursor.fetchall()
    conn.close()

    return render_template("records.html", records=rows)


# -----------------------------------
# ADMIN PANEL
# -----------------------------------

@app.route("/admin")
def admin_panel():
    if "user_id" not in session or session.get("role") != "admin":
        return "Access Denied"

    conn = sqlite3.connect("health.db")
    cursor = conn.cursor()

    cursor.execute("SELECT id, username, role FROM users")
    users = cursor.fetchall()

    cursor.execute("""
    SELECT records.id, users.username, records.risk_level, records.timestamp
    FROM records
    JOIN users ON records.user_id = users.id
    ORDER BY records.id DESC
    """)
    records = cursor.fetchall()

    conn.close()

    return render_template("admin.html", users=users, records=records)


# -----------------------------------

if __name__ == "__main__":
    app.run(debug=True)
