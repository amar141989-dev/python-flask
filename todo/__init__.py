from flask import Flask
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)

app.config["SECRET_KEY"]="thisissecret"
app.config["SQLALCHEMY_DATABASE_URI"]="sqlite:///todo.db"

db= SQLAlchemy(app)

from todo import routes