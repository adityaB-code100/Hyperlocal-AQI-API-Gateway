from flask import Flask, abort, jsonify, request, redirect, url_for, session, render_template, flash
from werkzeug.security import generate_password_hash, check_password_hash
from bson.objectid import ObjectId
from functools import wraps
from pymongo import MongoClient
import os, json, traceback, logging, re
from datetime import datetime

# Your custom imports
#from utils import get_html_page
from atlas import get_mongo_uri
from get_from_db import get_aqi_data, get_aqi_by_village
from get_health_alerts_institution import get_health_alert_institution
from get_health_alert import get_health_alert_personal
from notes_db import add_note, get_notes_by_user, update_note, delete_note
from get_note import get_notes_for_matching_aqi
# import threading, time

# ----------------- Flask App -----------------
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'fallback-secret-key-for-development')
mongo_uri = get_mongo_uri()
client = MongoClient(mongo_uri)

# Select DB from URI or explicitly
db = client["AQI_Project"]

# Collections
users_collection = db.users
institutions_collection = db.institutions
notes_collection = db.notes
# # 
@app.route("/health")
def health():
    return "OK", 200


def log_error(e):
    logging.error(str(e), exc_info=True)



# ----------------- Helpers -----------------
def get_current_date():
    return datetime.now().strftime("%d-%m-%Y")

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "type" not in session:
            flash("Please login first!", "danger")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function



# ----------------- Routes -----------------

@app.route("/register", methods=["GET", "POST"])
def register():
    try:
        if request.method == "POST":
            reg_type = request.form.get("reg_type")
            if reg_type == "personal":
                if users_collection.find_one({"email": request.form["email"]}):
                    flash("Email already exists! Please login.", "danger")
                    return redirect(url_for("login"))
                data = {
                    "name": request.form["name"],
                    "email": request.form["email"],
                    "mobile": request.form["mobile"],
                    "village": request.form["village"],
                    "disease": request.form["disease"],
                    "language": request.form["target"],
                    "age": request.form["age"],
                    "password": generate_password_hash(request.form["password"])
                }
                users_collection.insert_one(data)
                flash("Personal account registered successfully!", "success")
                return redirect(url_for("login"))
            elif reg_type == "institution":
                if institutions_collection.find_one({"email": request.form["email"]}):
                    flash("Email already exists! Please login.", "danger")
                    return redirect(url_for("login"))
                data = {
                    "institution_name": request.form["institution_name"],
                    "institution_type": request.form["institution_type"],
                    "village": request.form["village"],
                    "address": request.form["address"],
                    "email": request.form["email"],
                    "contact": request.form["contact"],
                    "password": generate_password_hash(request.form["password"])
                }
                institutions_collection.insert_one(data)
                flash("Institution account registered successfully!", "success")
                return redirect(url_for("login"))
        return render_template("register.html")
    except Exception as e:
        log_error(e)
        flash("Error during registration.", "danger")
        return redirect(url_for("register"))

@app.route("/login", methods=["GET", "POST"])
def login():
    try:
        if request.method == "POST":
            login_type = request.form.get("login_type")
            email = request.form["email"]
            password = request.form["password"]
            if login_type == "personal":
                user = users_collection.find_one({"email": email})
                if user and check_password_hash(user["password"], password):
                    session["user"] = str(user["_id"])
                    session["type"] = "personal"
                    flash(f"Welcome, {user['name']}!", "success")
                    return redirect(url_for("dashboard", village=user["village"], date=get_current_date()))
            elif login_type == "institution":
                inst = institutions_collection.find_one({"email": email})
                if inst and check_password_hash(inst["password"], password):
                    session["institution"] = str(inst["_id"])
                    session["type"] = "institution"
                    flash(f"Welcome, {inst['institution_name']}!", "success")
                    return redirect('/')
            flash("Invalid credentials!", "danger")
        return render_template("login.html")
    except Exception as e:
        log_error(e)
        flash("Error during login.", "danger")
        return redirect(url_for("login"))

@app.route("/forgot", methods=["GET", "POST"])
def forgot_password():
    try:
        if request.method == "POST":
            account_type = request.form.get("account_type")
            email = request.form["email"]
            new_password = generate_password_hash(request.form["new_password"])
            if account_type == "personal":
                users_collection.update_one({"email": email}, {"$set": {"password": new_password}})
            elif account_type == "institution":
                institutions_collection.update_one({"email": email}, {"$set": {"password": new_password}})
            flash("Password updated successfully!", "success")
            return redirect(url_for("login"))
        return render_template("forgot.html")
    except Exception as e:
        log_error(e)
        flash("Error updating password.", "danger")
        return redirect(url_for("forgot_password"))

@app.route("/edit", methods=["GET", "POST"])
@login_required
def edit_profile():
    try:
        if session.get("type") == "personal":
            user = users_collection.find_one({"_id": ObjectId(session["user"])})
            if request.method == "POST":
                update_data = {
                    "name": request.form["name"],
                    "mobile": request.form["mobile"],
                    "village": request.form["village"],
                    "disease": request.form["disease"],
                    "language": request.form["target"],
                    "age": request.form["age"]
                }
                if request.form.get("password"):
                    update_data["password"] = generate_password_hash(request.form["password"])
                users_collection.update_one({"_id": user["_id"]}, {"$set": update_data})
                flash("Profile updated successfully!", "success")
                return redirect(url_for("profile"))
            return render_template("edit_personal.html", user=user)
        elif session.get("type") == "institution":
            inst = institutions_collection.find_one({"_id": ObjectId(session["institution"])})
            if request.method == "POST":
                update_data = {
                    "institution_name": request.form["institution_name"],
                    "institution_type": request.form["institution_type"],
                    "contact": request.form["contact"]
                }
                if request.form.get("password"):
                    update_data["password"] = generate_password_hash(request.form["password"])
                institutions_collection.update_one({"_id": inst["_id"]}, {"$set": update_data})
                flash("Institution profile updated successfully!", "success")
                return redirect(url_for("profile"))
            return render_template("edit_institution.html", inst=inst)
        return redirect(url_for("login"))
    except Exception as e:
        log_error(e)
        flash("Error updating profile.", "danger")
        return redirect(url_for("profile"))

@app.route("/logout")
def logout():
    try:
        session.clear()
        flash("Logged out successfully!", "info")
        return redirect(url_for("dashboard"))
    except Exception as e:
        log_error(e)
        flash("Error during logout.", "danger")
        return redirect(url_for("dashboard"))

@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    try:
        if session.get("type") == "personal":
            user = users_collection.find_one({"_id": ObjectId(session["user"])})
            if not user:
                return "User not found", 404
            village = user["village"]
            date = get_current_date()
            dict1 = get_aqi_data(date, village, mongo_uri=get_mongo_uri(),
                                 db_name="AQI_Project", collection_name="processed_data")
            
            # Handle case where get_aqi_data returns None
            if dict1 is None:
                dict1 = {}
            
            aqi_all = dict1.get('village_aqi_data', {})
            aqi = aqi_all.get(village)
            health_alert = get_health_alert_personal(aqi, 'general')
            personalise = get_health_alert_personal(aqi, user['disease']) if user['disease'] else None
            note = get_notes_for_matching_aqi(session.get("user"), village)
            return render_template("user_profile.html", user=user, health_alert=health_alert,
                                   personalise=personalise, **dict1, note=note, date=date)
        elif session.get("type") == "institution":
            inst = institutions_collection.find_one({"_id": ObjectId(session["institution"])})
            if not inst:
                return "Institution not found", 404
            village = inst["village"]
            date = get_current_date()
            dict1 = get_aqi_data(date, village, mongo_uri=get_mongo_uri(),
                                 db_name="AQI_Project", collection_name="processed_data")
            
            # Handle case where get_aqi_data returns None
            if dict1 is None:
                dict1 = {}
            
            aqi_all = dict1.get('village_aqi_data', {})
            aqi = aqi_all.get(village)
            personalise = get_health_alert_institution(aqi, 'general') if inst['institution_type'] else None
            institute_alert = get_health_alert_institution(aqi, inst['institution_type'])
            return render_template("institution_profile.html", inst=inst, **dict1,
                                   institute_alert=institute_alert, personalise=personalise, date=date)
        return redirect(url_for("login"))
    except Exception as e:
        log_error(e)
        flash("Error loading profile.", "danger")
        return redirect(url_for("dashboard"))

@app.route("/", methods=["GET", "POST"])
def dashboard():
        date=get_current_date()
    
        if request.method == "POST":
            village = request.form.get("village")
            date = request.form.get("date")
            return redirect(url_for("dashboard", village=village, date=date))
        else:
            village = request.args.get("village", "Pune")
            date = request.args.get("date", get_current_date())

        dict1 = get_aqi_data(date, village, mongo_uri=get_mongo_uri(),
                             db_name="AQI_Project", collection_name="processed_data")
        
        # Handle case where get_aqi_data returns None
        if dict1 is None:
            dict1 = {}
        
        aqi_all = dict1.get('village_aqi_data', {})
        aqi = aqi_all.get(village)
        health_alert = get_health_alert_personal(aqi, 'general')
        #print(**dict1)
        # Ensure date is passed to the template
        return render_template("aqi.html", **dict1, health_alert=health_alert)
   

@app.route('/coverage')
def coverage():
    try:
        date = get_current_date()
        village = "Pune"
        dict1 = get_aqi_data(date, village, mongo_uri=get_mongo_uri(),
                             db_name="AQI_Project", collection_name="processed_data")
            
        # Handle case where get_aqi_data returns None
        if dict1 is None:
            dict1 = {}
            
        return render_template('coverage.html', **dict1, date=date)
    except Exception as e:
        log_error(e)
        flash("Error loading coverage page.", "danger")
        return redirect(url_for("dashboard"))

@app.route('/about')
def about():
    return render_template('about.html')

# ---------- Notes Routes ----------
@app.route("/note/add", methods=["POST"])
@login_required
def add_note_route():
    try:
        user_id = session.get("user")
        title = request.form.get("title")
        content = request.form.get("content")
        if not title or not content:
            flash("Title and Content are required!", "danger")
            return redirect(url_for("note"))
        user = users_collection.find_one({"_id": ObjectId(user_id)})
        if not user:
            return "User not found", 404
        village = user["village"]
        date = get_current_date()
        dict1 = get_aqi_data(date, village, mongo_uri=get_mongo_uri(),
                             db_name="AQI_Project", collection_name="processed_data")
        
        # Handle case where get_aqi_data returns None
        if dict1 is None:
            dict1 = {}
        
        live_aqi = dict1.get("live_AQI", None)
        note_data = {
            "user_id": user_id,
            "title": title,
            "content": content,
            "village": village,
            "live_aqi": live_aqi,
            "created_at":  get_current_date()
        }
        notes_collection.insert_one(note_data)
        flash("Note added successfully with AQI data!", "success")
        return redirect(url_for("note"))
    except Exception as e:
        log_error(e)
        flash("Error adding note.", "danger")
        return redirect(url_for("note"))

@app.route("/note/edit/<id>", methods=["POST"])
@login_required
def edit_note_route(id):
    try:
        title = request.form.get("title")
        content = request.form.get("content")
        update_note(notes_collection, id, title, content)
        flash("Note updated successfully!", "info")
        return redirect(url_for("note"))
    except Exception as e:
        log_error(e)
        flash("Error updating note.", "danger")
        return redirect(url_for("note"))

@app.route("/note/delete/<id>")
@login_required
def delete_note_route(id):
    try:
        delete_note(notes_collection, id)
        flash("Note deleted successfully!", "warning")
        return redirect(url_for("note"))
    except Exception as e:
        log_error(e)
        flash("Error deleting note.", "danger")
        return redirect(url_for("note"))

@app.route('/note')
@login_required
def note():
    try:
        if session.get("type") == "personal":
            user = users_collection.find_one({"_id": ObjectId(session["user"])})
        if not user:
            return "User not found", 404
        name = user["name"]
        return render_template('note.html', name=name, date=get_current_date())
    except Exception as e:
        log_error(e)
        flash("Error loading notes.", "danger")
        return redirect(url_for("dashboard"))

# ---------- Chatbot ----------




# ---------- Compare ----------
@app.route("/compare", methods=["GET", "POST"])
def compare():
    try:
        if request.method == "POST":
            village1 = request.form.get("village1")
            village2 = request.form.get("village2")
            village1_data = get_aqi_data(get_current_date(), village1, mongo_uri=get_mongo_uri(),
                                        db_name="AQI_Project", collection_name="processed_data")
            village2_data = get_aqi_data(get_current_date(), village2, mongo_uri=get_mongo_uri(),
                                        db_name="AQI_Project", collection_name="processed_data")
            
            # Handle case where get_aqi_data returns None
            if village1_data is None:
                village1_data = {}
            if village2_data is None:
                village2_data = {}
            
            return render_template("compare.html", village1=village1_data, village2=village2_data)
        else:
            return render_template('compare_form.html')
    except Exception as e:
        log_error(e)
        flash("Error comparing AQI data.", "danger")
        return redirect(url_for("dashboard"))

# ----------------- Error Handlers -----------------
@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html"), 404

@app.errorhandler(500)
def internal_server_error(e):
    log_error(e)
    return render_template("500.html"), 500

@app.errorhandler(Exception)
def handle_exception(e):
    log_error(e)
    flash("An unexpected error occurred. Please try again.", "danger")
    return redirect(url_for("dashboard"))

# ----------------- Disable Caching -----------------
@app.after_request
def add_header(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response

# ----------------- Run App -----------------
if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=False)

