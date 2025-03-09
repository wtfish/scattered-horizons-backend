from flask import request, jsonify
from flask_jwt_extended import create_access_token
from werkzeug.security import generate_password_hash, check_password_hash
from google.oauth2 import id_token
from google.auth.transport import requests
from app.models.user import User
from app.db import db
from datetime import datetime
import pytz
import os

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")

def get_utc_timestamp():
    """Returns current UTC timestamp in ISO 8601 format."""
    return datetime.now(pytz.utc).isoformat()

def generate_jwt(user):
    """Generates JWT token for authentication."""
    return create_access_token(identity={"user_id": user.id, "email": user.email, "name": user.name})

def google_login():
    """Authenticate user using Google OAuth2."""
    token = request.json.get("token")

    try:
        id_info = id_token.verify_oauth2_token(token, requests.Request(), GOOGLE_CLIENT_ID)
        user = User.query.filter_by(email=id_info["email"]).first()

        if not user:
            user = User(email=id_info["email"], name=id_info.get("name", ""), google_id=id_info["sub"])
            db.session.add(user)
            db.session.commit()

        access_token = generate_jwt(user)
        return jsonify({
            "status": "success",
            "message": "Google login successful",
            "access_token": access_token,
            "user": {
                "email": user.email,
                "name": user.name
            },
            "timestamp": get_utc_timestamp()
        }), 200

    except Exception as e:
        return jsonify({
            "status": "error",
            "message": "Invalid Google Token",
            "details": str(e),
            "timestamp": get_utc_timestamp()
        }), 401

def register():
    """Registers a new user using email and password."""
    data = request.json
    email = data.get("email")
    password = data.get("password")
    name = data.get("name")

    if User.query.filter_by(email=email).first():
        return jsonify({
            "status": "error",
            "message": "Email already exists",
            "timestamp": get_utc_timestamp()
        }), 400

    hashed_password = generate_password_hash(password)
    user = User(email=email, password=hashed_password, name=name)
    db.session.add(user)
    db.session.commit()

    response = jsonify({
        "status": "success",
        "message": "User registered successfully",
        "timestamp": get_utc_timestamp()
    })

    return response, 201

def login():
    """Authenticates user using email and password."""
    data = request.json
    email = data.get("email")
    password = data.get("password")

    user = User.query.filter_by(email=email).first()

    if not user or not check_password_hash(user.password, password):
        return jsonify({
            "status": "error",
            "message": "Invalid credentials",
            "timestamp": get_utc_timestamp()
        }), 401

    response = jsonify({
        "status": "success",
        "message": "Login successful",
        "user": {
            "name": user.name  # Do NOT expose email
        },
        "timestamp": get_utc_timestamp()
    })
    # Generate JWT token
    access_token = create_access_token(identity=user.id)
    # Store JWT securely in HttpOnly Cookie
    response.set_cookie(
        "access_token", access_token,
        httponly=True, secure=True, samesite="Strict"
    )

    return response, 200

def logout():
    """Logs out the user by clearing the JWT cookie."""
    
    response = jsonify({
        "status": "success",
        "message": "Logged out successfully",
        "timestamp": get_utc_timestamp()
    })

    # Clear JWT from cookies
    response.set_cookie(
        "access_token", "", httponly=True, secure=True, samesite="Strict", expires=0
    )

    return response, 200
