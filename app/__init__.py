from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from app.models.user import db, User
from app.routes.auth import auth_bp
from app.config import Config
from app.db import init_db

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    CORS(app)
    jwt = JWTManager(app)
    db.init_db(app)
    
    
    app.register_blueprint(auth_bp, url_prefix="/auth")

    @app.route('/login', methods=['POST'])
    def login():
        data = request.get_json()
        email = data.get("email")
        password = data.get("password")
        
        user = User.query.filter_by(email=email).first()
        if not user or not user.check_password(password):
            return jsonify({"status": "error", "message": "Invalid credentials"}), 401
        
        access_token = create_access_token(identity=email)
        return jsonify({"token": access_token, "status": "success"})
    
    @app.route('/logout', methods=['POST'])
    @jwt_required()
    def logout():
        return jsonify({"status": "success", "message": "Logged out successfully"})
    
    @app.route('/protected', methods=['GET'])
    @jwt_required()
    def protected():
        current_user = get_jwt_identity()
        return jsonify({"status": "success", "message": "Access granted", "user": current_user})
    
    return app
