import os
import os
import sqlite3
from datetime import datetime, timezone
from functools import wraps

from flask import (
    Flask, render_template, request,
    redirect, url_for, session, flash,
    jsonify, abort
)
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__, template_folder="templates",)
app.secret_key = os.environ.get(
    "SAWTNA_SECRET_KEY", "change-this-secret-before-deployment"
)

DB_PATH = os.path.join(app.root_path, "instance", "sawtna.db")


def db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys=ON")
    return con


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def init_db():
    with db() as con:
        con.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            coins INTEGER NOT NULL DEFAULT 100
        );

        CREATE TABLE IF NOT EXISTS rooms (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT DEFAULT '',
            owner_id INTEGER NOT NULL REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS members (
            room_id INTEGER NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            speaker INTEGER DEFAULT 0,
            muted INTEGER DEFAULT 0,
            PRIMARY KEY(room_id, user_id)
        );

        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            room_id INTEGER NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
            user_id INTEGER NOT NULL REFERENCES users(id),
            body TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS moderators (
            room_id INTEGER NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            PRIMARY KEY(room_id, user_id)
        );

        CREATE TABLE IF NOT EXISTS gifts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            room_id INTEGER NOT NULL REFERENCES rooms(id),
            sender_id INTEGER NOT NULL REFERENCES users(id),
            recipient_id INTEGER NOT NULL REFERENCES users(id),
            name TEXT NOT NULL,
            price INTEGER NOT NULL,
            created_at TEXT NOT NULL
        );
        """)


def get_user():
    uid = session.get("user_id")
    if not uid:
        return None
    with db() as con:
        row = con.execute(
            "SELECT id, username, coins FROM users WHERE id=?",
            (uid,)
        ).fetchone()
        return dict(row) if row else None


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper


@app.route("/")
def index():
    user = get_user()
    with db() as con:
        rooms = con.execute("""
            SELECT r.*, u.username AS owner,
                   COUNT(m.user_id) AS member_count
            FROM rooms r
            JOIN users u ON u.id=r.owner_id
            LEFT JOIN members m ON m.room_id=r.id
            GROUP BY r.id
            ORDER BY r.id DESC
        """).fetchall()
    return render_template("index.html", user=user, rooms=rooms)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if len(username) < 3 or len(username) > 24:
            flash("اسم المستخدم يجب أن يكون بين 3 و24 حرفًا.")
        elif len(password) < 8:
            flash("كلمة المرور يجب ألا تقل عن 8 أحرف.")
        else:
            try:
                with db() as con:
                    cur = con.execute(
                        """INSERT INTO users(username,password_hash)
                           VALUES(?,?)""",
                        (username, generate_password_hash(password))
                    )
                    session.clear()
                    session["user_id"] = cur.lastrowid
                return redirect(url_for("index"))
            except sqlite3.IntegrityError:
                flash("اسم المستخدم موجود بالفعل.")

    return render_template("register.html", user=get_user())


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        with db() as con:
            user = con.execute(
                "SELECT * FROM users WHERE username=?",
                (username,)
            ).fetchone()

        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            return redirect(url_for("index"))

        flash("بيانات تسجيل الدخول غير صحيحة.")

    return render_template("login.html", user=get_user())


@app.post("/logout")
@login_required
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.post("/rooms/create")
@login_required
def create_room():
    name = request.form.get("name", "").strip()
    description = request.form.get("description", "").strip()

    if not name or len(name) > 60:
        flash("أدخل اسمًا صالحًا للغرفة.")
        return redirect(url_for("index"))

    with db() as con:
        cur = con.execute(
            """INSERT INTO rooms(name,description,owner_id)
               VALUES(?,?,?)""",
            (name, description, session["user_id"])
        )
        room_id = cur.lastrowid

        con.execute(
            "INSERT INTO moderators(room_id,user_id) VALUES(?,?)",
            (room_id, session["user_id"])
        )
        con.execute(
            "INSERT INTO members(room_id,user_id,speaker) VALUES(?,?,1)",
            (room_id, session["user_id"])
        )

    return redirect(url_for("room", room_id=room_id))


@app.route("/rooms/<int:room_id>")
@login_required
def room(room_id):
    user = get_user()

    with db() as con:
        room_data = con.execute("""
            SELECT r.*,u.username AS owner
            FROM rooms r JOIN users u ON u.id=r.owner_id
            WHERE r.id=?
        """, (room_id,)).fetchone()

        if not room_data:
            abort(404)

        con.execute(
            """INSERT INTO members(room_id,user_id)
               VALUES(?,?) ON CONFLICT DO NOTHING""",
            (room_id, user["id"])
        )

        members = con.execute("""
            SELECT u.id,u.username,m.speaker,m.muted
            FROM members m JOIN users u ON u.id=m.user_id
            WHERE m.room_id=?
            ORDER BY m.speaker DESC,u.username
        """, (room_id,)).fetchall()

        messages = con.execute("""
            SELECT msg.id,msg.body,msg.created_at,u.username
            FROM messages msg JOIN users u ON u.id=msg.user_id
            WHERE msg.room_id=?
            ORDER BY msg.id DESC LIMIT 50
        """, (room_id,)).fetchall()

        moderator = con.execute(
            "SELECT 1 FROM moderators WHERE room_id=? AND user_id=?",
            (room_id, user["id"])
        ).fetchone()

    return render_template(
        "room.html",
        user=user,
        room=room_data,
        members=members,
        messages=list(reversed(messages)),
        is_moderator=bool(moderator)
    )


@app.post("/rooms/<int:room_id>/leave")
@login_required
def leave_room(room_id):
    with db() as con:
        con.execute(
            "DELETE FROM members WHERE room_id=? AND user_id=?",
            (room_id, session["user_id"])
        )
    return redirect(url_for("index"))


@app.post("/api/rooms/<int:room_id>/messages")
@login_required
def send_message(room_id):
    body = request.form.get("body", "").strip()

    if not body or len(body) > 1000:
        return jsonify(error="رسالة غير صالحة"), 400

    with db() as con:
        member = con.execute(
            "SELECT 1 FROM members WHERE room_id=? AND user_id=?",
            (room_id, session["user_id"])
        ).fetchone()

        if not member:
            return jsonify(error="انضم إلى الغرفة أولًا"), 403

        cur = con.execute(
            """INSERT INTO messages(room_id,user_id,body,created_at)
               VALUES(?,?,?,?)""",
            (room_id, session["user_id"], body, now())
        )

        msg = con.execute("""
            SELECT m.id,m.body,m.created_at,u.username
            FROM messages m JOIN users u ON u.id=m.user_id
            WHERE m.id=?
        """, (cur.lastrowid,)).fetchone()

    return jsonify(message=dict(msg))


@app.get("/api/rooms/<int:room_id>/updates")
@login_required
def updates(room_id):
    try:
        after = max(0, int(request.args.get("after", 0)))
    except ValueError:
        after = 0

    with db() as con:
        member = con.execute(
            "SELECT 1 FROM members WHERE room_id=? AND user_id=?",
            (room_id, session["user_id"])
        ).fetchone()

        if not member:
            return jsonify(error="غير مسموح"), 403

        messages = con.execute("""
            SELECT m.id,m.body,m.created_at,u.username
            FROM messages m JOIN users u ON u.id=m.user_id
            WHERE m.room_id=? AND m.id>?
            ORDER BY m.id LIMIT 100
        """, (room_id, after)).fetchall()

        members = con.execute("""
            SELECT u.id,u.username,m.speaker,m.muted
            FROM members m JOIN users u ON u.id=m.user_id
            WHERE m.room_id=?
        """, (room_id,)).fetchall()

    return jsonify(
        messages=[dict(m) for m in messages],
        members=[dict(m) for m in members]
    )


@app.post("/api/rooms/<int:room_id>/speaker")
@login_required
def speaker(room_id):
    uid = session["user_id"]

    with db() as con:
        member = con.execute(
            "SELECT speaker FROM members WHERE room_id=? AND user_id=?",
            (room_id, uid)
        ).fetchone()

        if not member:
            return jsonify(error="انضم إلى الغرفة أولًا"), 403

        if member["speaker"]:
            con.execute(
                "UPDATE members SET speaker=0 WHERE room_id=? AND user_id=?",
                (room_id, uid)
            )
            state = False
        else:
            count = con.execute(
                "SELECT COUNT(*) AS n FROM members WHERE room_id=? AND speaker=1",
                (room_id,)
            ).fetchone()["n"]

            if count >= 8:
                return jsonify(error="المقاعد ممتلئة"), 409

            con.execute(
                "UPDATE members SET speaker=1 WHERE room_id=? AND user_id=?",
                (room_id, uid)
            )
            state = True

    return jsonify(speaker=state)


@app.post("/api/rooms/<int:room_id>/mute/<int:target_id>")
@login_required
def mute(room_id, target_id):
    uid = session["user_id"]

    with db() as con:
        room_data = con.execute(
            "SELECT owner_id FROM rooms WHERE id=?", (room_id,)
        ).fetchone()

        moderator = con.execute(
            "SELECT 1 FROM moderators WHERE room_id=? AND user_id=?",
            (room_id, uid)
        ).fetchone()

        if not room_data:
            return jsonify(error="الغرفة غير موجودة"), 404

        if room_data["owner_id"] != uid and not moderator:
            return jsonify(error="هذه الخاصية للمشرفين فقط"), 403

        member = con.execute(
            "SELECT muted FROM members WHERE room_id=? AND user_id=?",
            (room_id, target_id)
        ).fetchone()

        if not member:
            return jsonify(error="المستخدم غير موجود"), 404

        state = 0 if member["muted"] else 1
        con.execute(
            "UPDATE members SET muted=? WHERE room_id=? AND user_id=?",
            (state, room_id, target_id)
        )

    return jsonify(muted=bool(state))


@app.post("/api/rooms/<int:room_id>/gift")
@login_required
def gift(room_id):
    try:
        recipient = int(request.form.get("recipient_id", ""))
    except ValueError:
        return jsonify(error="اختر مستلمًا صالحًا"), 400

    gifts = {
        "rose": ("وردة 🌹", 10),
        "heart": ("قلب ❤️", 25),
        "star": ("نجمة ⭐", 50)
    }

    gift_id = request.form.get("gift_name")

    if gift_id not in gifts:
        return jsonify(error="هدية غير صالحة"), 400

    sender = session["user_id"]

    if sender == recipient:
        return jsonify(error="لا يمكنك إرسال هدية لنفسك"), 400

    name, price = gifts[gift_id]
    con = db()

    try:
        con.execute("BEGIN IMMEDIATE")

        member = con.execute(
            "SELECT 1 FROM members WHERE room_id=? AND user_id=?",
            (room_id, recipient)
        ).fetchone()

        balance = con.execute(
            "SELECT coins FROM users WHERE id=?", (sender,)
        ).fetchone()

        if not member or not balance:
            con.rollback()
            return jsonify(error="المستلم غير موجود في الغرفة"), 404

        if balance["coins"] < price:
            con.rollback()
            return jsonify(error="رصيد العملات غير كافٍ"), 409

        con.execute(
            "UPDATE users SET coins=coins-? WHERE id=?",
            (price, sender)
        )
        con.execute("""
            INSERT INTO gifts(room_id,sender_id,recipient_id,name,price,created_at)
            VALUES(?,?,?,?,?,?)
        """, (room_id, sender, recipient, name, price, now()))

        con.commit()
        return jsonify(ok=True, gift=name, price=price)

    except sqlite3.Error:
        con.rollback()
        return jsonify(error="حدث خطأ"), 500
    finally:
        con.close()


init_db()

if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5000)