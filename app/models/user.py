import app.db as db

class User(db.db.Model):
    id = db.db.Column(db.db.Integer, primary_key=True)
    email = db.db.Column(db.db.String(120), unique=True, nullable=False)
    password = db.db.Column(db.db.String(256))  # Hashed password
    name = db.db.Column(db.db.String(80))
    google_id = db.db.Column(db.db.String(256), unique=True, nullable=True)  # If logging in via Google