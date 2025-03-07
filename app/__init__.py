from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_wtf.csrf import CSRFProtect
from flask_caching import Cache
from flask_apscheduler import APScheduler
import mysql.connector

app = Flask(__name__)
app.config['SECRET_KEY'] = 'KhadimBamba'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://root@localhost/gestion_recursos_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['CACHE_TYPE'] = 'SimpleCache'
app.config['CACHE_DEFAULT_TIMEOUT'] = 60

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'iniciar_sesion'

@login_manager.user_loader
def load_user(user_id):
    from app.models import Usuario
    return Usuario.query.get(int(user_id))

csrf = CSRFProtect(app)
cache = Cache(app)
scheduler = APScheduler()
scheduler.init_app(app)
scheduler.start()

def create_database():
    try:
        connection = mysql.connector.connect(host="localhost", user="root", password="")
        cursor = connection.cursor()
        cursor.execute("CREATE DATABASE IF NOT EXISTS gestion_recursos_db")
        cursor.close()
        connection.close()
        print("Base de datos 'gestion_recursos_db' creada o ya existe.")
    except mysql.connector.Error as err:
        print(f"Error al crear la base de datos: {err}")

from app import routes, models