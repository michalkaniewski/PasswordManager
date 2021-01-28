from app import app
import os
import getpass
import pymysql
from flask import jsonify
from flask import render_template
from flask import request, make_response
from .db_dao import DbDAO
import random
import string
import re

dao = DbDAO()

@app.before_request
def before_request_fun():
    session_id = request.cookies.get("session_id")
    if session_id:
        dao.refresh_session(session_id)
    dao.delete_old_sessions()

@app.route("/", methods=["GET"])
def index():
    return render_template("home.html")

@app.route("/register", methods=["GET"])
def register_form():
    return render_template("register-form.html")

@app.route("/register", methods=["POST"])
def register():
    username = request.form.get("username")
    password = request.form.get("password")
    repassword = request.form.get("repassword")
    email = request.form.get("email")
    if not (username and password and repassword and email):
        response = make_response("Missing data", 302)
        response.headers['location'] = "/register"
        return response
    if not password == repassword:
        response = make_response("Passwords not matching", 302)
        response.headers['location'] = "/register"
        return response
    if not (re.compile("^[a-z]{3,20}$").match(username)
    and re.compile("^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#$%^&*_=+-]).{8,}$").match(password)
    and re.compile("^[A-Za-z0-9.]{1,}@[0-9a-zA-Z.]{1,}$").match(email)):
        response = make_response("Invalid data", 302)
        response.headers['location'] = "/register"
        return response
    if not dao.is_username_unique(username):
        response = make_response("Login is taken", 302)
        response.headers['location'] = "/register"
        return response
     
    dao.register_new_user(username, password, email)
    response = make_response('User registered', 302)
    response.headers['location'] = '/login'
    return response

@app.route("/login", methods=["GET"])
def login_form():
    return render_template("login-form.html")

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")

    if not (username and password):
        response = make_response("Pass login and password", 302)
        response.headers['location'] = "/login"
        return response
    if dao.is_account_locked(username):
        response = make_response("Locked account", 302)
        response.headers['location'] = "/login"
        return response
    if not dao.validate_password(username, password):
        response = make_response("Bad credentials", 302)
        response.headers['location'] = "/login"
        return response
    if dao.is_user_logged_in(username):
        response = make_response("You are logged in somewhere else", 302)
        response.headers['location'] = "/login"
        return response
    session_id = ''.join(random.choices(string.ascii_uppercase + string.digits, k=32))
    dao.set_session(session_id, username)
    response = make_response('Logged in correctly', 302)
    response.set_cookie("session_id", session_id, max_age=1800, secure=True, httponly=True)
    response.headers['location'] = '/'

    return response

@app.route("/logout")
def logout():
    session_id = request.cookies.get('session_id')
    if session_id:
        dao.delete_session(session_id)
        response = make_response('Logged out correctly', 302)
        response.set_cookie("session_id", "", max_age=0)
    else:
        response = make_response('No user logged in', 302)
    response.headers['location'] = '/'
    return response

@app.route("/dashboard", methods=["GET"]) 
def dashboard_page():
    session_id = request.cookies.get('session_id')
    if not dao.get_user(session_id):
        response = make_response("Not authorized", 302)
        response.headers['location'] = "/login"
        return response
    passwords = dao.get_users_passwords(session_id)
    return render_template("dashboard.html", data=passwords)

@app.route("/password/<pass_id>", methods=["POST"])
def get_password(pass_id):
    session_id = request.cookies.get('session_id')
    uid = dao.get_user(session_id)
    key = request.get_json().get("key")
    if not key:
        response = make_response("Give key", 302)
        response.headers['location'] = "/login"
        return response
    if not uid:
        response = make_response("Not authorized", 302)
        response.headers['location'] = "/login"
        return response
    password = dao.get_password(pass_id, key, uid)
    return password

@app.route("/password", methods=["POST"])
def add_password():
    session_id = request.cookies.get('session_id')
    if not dao.get_user(session_id):
        response = make_response("Not authorized", 302)
        response.headers['location'] = "/login"
        return response
    service = request.form.get("service")
    password = request.form.get("password")
    password2 = request.form.get("repassword")
    mast_key = request.form.get("masterpassword")
    mast_key2 = request.form.get("remasterpassword")
    if not (service and password and password2 and mast_key and mast_key2):
        response = make_response("Missing data", 302)
        response.headers['location'] = "/dashboard"
        return response
    if not password == password2:
        response = make_response("Passwords not equal", 302)
        response.headers['location'] = "/dashboard"
        return response
    if not mast_key == mast_key2:
        response = make_response("Master keys not equal", 302)
        response.headers['location'] = "/dashboard"
        return response
    if not (re.compile("^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#$%^&*_=+-]).{8,}$").match(mast_key)
    and len(password) <= 64):
        response = make_response("Invalid data", 302)
        response.headers['location'] = "/dashboard"
        return response
    dao.add_password(session_id, service, password, mast_key)
    response = make_response("Password added", 302)
    response.headers['location'] = '/dashboard'
    return response
