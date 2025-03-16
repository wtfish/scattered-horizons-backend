from flask import Blueprint
from app.api import auth
from app.controller import index

index_bp = Blueprint("index_bp", __name__)

# Rute index
index_bp.route("/test/test", methods=["GET"])(index.test)
index_bp.route("/", methods=["GET"])(index.index)