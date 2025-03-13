from flask import Blueprint
from app.api import auth
from app.controller import index

index_bp = Blueprint("index_bp", __name__)

# Rute autentikasi
index_bp.route("/", methods=["GET"])(index.index)