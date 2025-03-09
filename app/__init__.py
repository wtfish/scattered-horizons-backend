from flask import Flask
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from app.models.user import db
from app.routes.auth import auth_bp
from app.config import Config
from app.db import init_db

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    CORS(app)
    JWTManager(app)

    db.init_db(app)
    # Register Blueprints
    app.register_blueprint(auth_bp, url_prefix="/auth")

    return app
