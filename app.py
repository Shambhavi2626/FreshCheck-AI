
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
        json.loads(row["payload"]) for row in rows
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
            (scan_id, session["user_id"])
        ).fetchone()

    if not row:
        return redirect(url_for("dashboard"))

    return render_template(
        "result.html",
        scan=json.loads(row["payload"])
    )


# ---------------- DASHBOARD STATISTICS API ----------------
@app.get("/api/admin/stats")
@login_required
def admin_stats():
    with get_db() as conn:
        users = conn.execute(
            "SELECT COUNT(*) AS total FROM users"
        ).fetchone()["total"]

        logins = conn.execute(
            "SELECT COUNT(*) AS total FROM login_events"
        ).fetchone()["total"]

        total_scans = conn.execute(
            "SELECT COUNT(*) AS total FROM scans"
        ).fetchone()["total"]

        rows = conn.execute(
            "SELECT payload FROM scans"
        ).fetchall()

    total_images = 0
    total_video_frames = 0

    for row in rows:
        data = json.loads(row["payload"])
        total_images += len(data.get("images", []))
        total_video_frames += len(data.get("video_frames", []))

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
    public = {"login", "register", "static"}

    if (
        request.endpoint
        and request.endpoint not in public
        and "user_id" not in session
    ):
        return redirect(url_for("login"))


# ---------------- FILE SIZE ERROR ----------------
@app.errorhandler(413)
def too_large(_error):
    return jsonify({
        "error": "Upload is too large. Maximum combined upload size is 150 MB."
    }), 413


# ---------------- INITIALIZE DATABASE ----------------
# Database environment variables must be configured before starting the app.
init_db()


# ---------------- RUN APPLICATION ----------------
if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        debug=False
    )
