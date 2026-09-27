import json
import secrets
from functools import wraps
from urllib.parse import quote

from flask import Flask, abort, flash, g, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from . import billing, checks, config, db, monitor, verify


def create_app(db_path=None, txt=None, run_checks=None):
    app = Flask(__name__)
    app.config["SECRET_KEY"] = config.SECRET_KEY
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    db_path = db_path or config.DATABASE
    txt = txt or checks.txt_records
    run_checks = run_checks or checks.run_all
    db.init(db_path)

    def conn():
        if "conn" not in g:
            g.conn = db.connect(db_path)
        return g.conn

    @app.teardown_appcontext
    def close(_exc):
        c = g.pop("conn", None)
        if c is not None:
            c.commit()
            c.close()

    @app.before_request
    def csrf():
        session.setdefault("csrf", secrets.token_urlsafe(16))
        if request.method == "POST" and request.endpoint != "stripe_webhook":
            if request.form.get("csrf") != session["csrf"]:
                abort(400)

    @app.after_request
    def security_headers(resp):
        # Practice what we preach.
        resp.headers.setdefault("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'")
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        return resp

    def current_user():
        uid = session.get("uid")
        return conn().execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone() if uid else None

    def login_required(fn):
        @wraps(fn)
        def wrapper(*a, **kw):
            user = current_user()
            if not user:
                return redirect(url_for("login"))
            return fn(user, *a, **kw)
        return wrapper

    def own_domain(user, domain_id):
        d = conn().execute("SELECT * FROM domains WHERE id = ? AND user_id = ?", (domain_id, user["id"])).fetchone()
        if not d:
            abort(404)
        return d

    @app.context_processor
    def inject():
        return {"user": current_user(), "plans": config.PLANS, "csrf_token": session.get("csrf")}

    @app.get("/")
    def index():
        return render_template("index.html")

    @app.route("/signup", methods=["GET", "POST"])
    def signup():
        if request.method == "POST":
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")
            if "@" not in email or len(password) < 8:
                flash("بريد غير صالح أو كلمة مرور أقل من 8 أحرف.")
            elif conn().execute("SELECT 1 FROM users WHERE email = ?", (email,)).fetchone():
                flash("هذا البريد مسجل بالفعل.")
            else:
                cur = conn().execute("INSERT INTO users (email, password_hash) VALUES (?, ?)",
                                     (email, generate_password_hash(password)))
                session.clear()
                session["uid"] = cur.lastrowid
                return redirect(url_for("dashboard"))
        return render_template("auth.html", mode="signup")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            email = request.form.get("email", "").strip().lower()
            row = conn().execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
            if row and check_password_hash(row["password_hash"], request.form.get("password", "")):
                session.clear()
                session["uid"] = row["id"]
                return redirect(url_for("dashboard"))
            flash("بيانات الدخول غير صحيحة.")
        return render_template("auth.html", mode="login")

    @app.post("/logout")
    def logout():
        session.clear()
        return redirect(url_for("index"))

    @app.get("/dashboard")
    @login_required
    def dashboard(user):
        domains = conn().execute("SELECT * FROM domains WHERE user_id = ? ORDER BY id", (user["id"],)).fetchall()
        links = {"pro": config.STRIPE_LINK_PRO, "business": config.STRIPE_LINK_BUSINESS}
        upgrade = {k: f"{v}?client_reference_id={user['id']}&prefilled_email={quote(user['email'])}"
                   for k, v in links.items() if v}
        return render_template("dashboard.html", domains=domains, upgrade=upgrade)

    @app.post("/domains")
    @login_required
    def add_domain(user):
        name = verify.normalize(request.form.get("domain", ""))
        count = conn().execute("SELECT COUNT(*) FROM domains WHERE user_id = ?", (user["id"],)).fetchone()[0]
        if not name:
            flash("اسم نطاق غير صالح.")
        elif count >= config.PLANS[user["plan"]]["domains"]:
            flash("وصلت للحد الأقصى من النطاقات في باقتك. قم بالترقية لإضافة المزيد.")
        elif conn().execute("SELECT 1 FROM domains WHERE user_id = ? AND name = ?", (user["id"], name)).fetchone():
            flash("النطاق مضاف بالفعل.")
        else:
            cur = conn().execute("INSERT INTO domains (user_id, name, token) VALUES (?, ?, ?)",
                                 (user["id"], name, verify.new_token()))
            return redirect(url_for("domain", domain_id=cur.lastrowid))
        return redirect(url_for("dashboard"))

    @app.get("/domains/<int:domain_id>")
    @login_required
    def domain(user, domain_id):
        d = own_domain(user, domain_id)
        report = conn().execute("SELECT * FROM reports WHERE domain_id = ? ORDER BY id DESC LIMIT 1",
                                (domain_id,)).fetchone()
        findings = json.loads(report["findings"]) if report else []
        order = {"high": 0, "medium": 1, "low": 2, "info": 3}
        findings.sort(key=lambda f: order[f["severity"]])
        return render_template("domain.html", d=d, report=report, findings=findings,
                               record_name=verify.record_name(d["name"]), record_value=verify.record_value(d["token"]))

    @app.post("/domains/<int:domain_id>/verify")
    @login_required
    def verify_domain(user, domain_id):
        d = own_domain(user, domain_id)
        if verify.is_verified(d["name"], d["token"], txt=txt):
            conn().execute("UPDATE domains SET verified_at = datetime('now') WHERE id = ?", (domain_id,))
            conn().commit()
            fresh = conn().execute("SELECT d.*, u.email FROM domains d JOIN users u ON u.id = d.user_id WHERE d.id = ?",
                                   (domain_id,)).fetchone()
            monitor.check_domain(conn(), fresh, run=run_checks)
            flash("تم التحقق من ملكية النطاق وتشغيل أول فحص.")
        else:
            flash("لم نجد سجل التحقق بعد. انتظر بضع دقائق بعد إضافته ثم أعد المحاولة.")
        return redirect(url_for("domain", domain_id=domain_id))

    @app.post("/domains/<int:domain_id>/scan")
    @login_required
    def scan(user, domain_id):
        d = own_domain(user, domain_id)
        if not d["verified_at"]:
            abort(403)
        recent = conn().execute("SELECT 1 FROM domains WHERE id = ? AND last_checked_at > datetime('now', '-1 hour')",
                                (domain_id,)).fetchone()
        if recent:
            flash("يمكن تشغيل فحص يدوي مرة كل ساعة.")
        else:
            fresh = conn().execute("SELECT d.*, u.email FROM domains d JOIN users u ON u.id = d.user_id WHERE d.id = ?",
                                   (domain_id,)).fetchone()
            monitor.check_domain(conn(), fresh, run=run_checks)
        return redirect(url_for("domain", domain_id=domain_id))

    @app.post("/domains/<int:domain_id>/delete")
    @login_required
    def delete_domain(user, domain_id):
        own_domain(user, domain_id)
        conn().execute("DELETE FROM domains WHERE id = ?", (domain_id,))
        return redirect(url_for("dashboard"))

    @app.post("/stripe/webhook")
    def stripe_webhook():
        try:
            event = billing.verify_signature(request.get_data(), request.headers.get("Stripe-Signature", ""),
                                             config.STRIPE_WEBHOOK_SECRET)
        except (billing.BadSignature, ValueError):
            abort(400)
        billing.apply_event(conn(), event)
        return {"ok": True}

    return app


def main():
    create_app().run(host="0.0.0.0", port=8000)


if __name__ == "__main__":
    main()
