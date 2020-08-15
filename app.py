from flask import Flask, session, redirect, url_for, render_template, request
import sqlite3

'''
pip uninstall Werkzeug
pip install install Werkzeug==0.16.0
'''

from werkzeug.security import check_password_hash, generate_password_hash

from helpers import *

conn = sqlite3.connect("db.sqlite3", check_same_thread=False)

c = conn.cursor()
app = Flask(__name__)
app.config["SECRET_KEY"] = "secretkey"


@app.route("/")
@login_required
def index():
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        # check if form is valid
            # if valid, proceed
            if not request.form.get("email") or not request.form.get("password") or not request.form.get("confirmation"):
                return "Please fill all fields"

            if request.form.get("password") != request.form.get("confirmation"):
                return "Password Confirmation doesn't match"
            # else, return error

        # check if email exist in database
            # if exist, return an error
            # else, proceed

            exist = c.execute("SELECT * FROM users WHERE email=:email", {"email": request.form.get("email")}).fetchall()

            if len(exist) != 0:
                return "User with this email already exist."


             # hash the password
            pwhash = generate_password_hash(request.form.get("password"), method="pbkdf2:sha256", salt_length=8)

            # insert the row
            c.execute("INSERT INTO users (email, password) VALUES (:email, :password)", {"email": request.form.get("email"), "password": pwhash})
            conn.commit()
            # return success
            return "Registered Successfully!"
    else:
        return render_template("register.html")


@app.route("/login", methods=["GET", 'POST'])
def login():

    if request.method == "POST":
        # check if is valid
        if not request.form.get("email") or not request.form.get("password"):
            return "Please fill the required fields"

        # check if email exyst in database
        user = c.execute("SELECT * FROM users WHERE email=:email", {"email": request.form.get("email")}).fetchall()

        if len(user) != 1:
            return "User doesn't exist"

        # check whether the password is same to password hash
        pwhash = user[0][2]
        if check_password_hash(pwhash, request.form.get("password")) == False:
            return "Wrong Password!!"

        # login the user using session
        session["user_id"] = user[0][0]

        # return success
        return "Logged In Successfully."

    else:
        return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))