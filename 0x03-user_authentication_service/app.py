#!/usr/bin/env python3
"""app module"""
from flask import Flask, jsonify, request, abort, make_response, redirect
from auth import Auth
app = Flask(__name__)
AUTH = Auth()


@app.route("/")
def home():
    """home route"""
    return jsonify({"message": "Bienvenue"})


@app.route("/users", methods=["POST"])
def users():
    """users route"""
    try:
        email = request.form["email"]
        AUTH.register_user(request.form["email"], request.form["password"])
        return jsonify({"email": email, "message": "user created"})
    except ValueError:
        return jsonify({"message": "email already registered"}), 400


@app.route("/sessions", methods=["POST"])
def login():
    """sessions route"""
    email = request.form["email"]
    if AUTH.valid_login(email, request.form["password"]):
        res = make_response(jsonify({"email": email, "message": "logged in"}))
        res.set_cookie("session_id", AUTH.create_session(email))
        return res
    abort(401)


@app.route("/sessions", methods=["DELETE"])
def logout():
    """logout"""
    user = AUTH.get_user_from_session_id(request.cookies["session_id"])
    if user:
        AUTH.destroy_session(user.id)
        return redirect("/")
    abort(403)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
