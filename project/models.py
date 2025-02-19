from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
import logging, os

app = Flask(__name__)
app.config.from_object(os.environ.get('CONFIG_CLASS') or 'config.Config')

db = SQLAlchemy(app)


class Usuario(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    usuario = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    contrasena = db.Column(db.String(255), nullable=False)
    rol = db.Column(db.Enum('administrador', 'usuario'), nullable=False, default='usuario')  # Valor por defecto
    fecha_creacion = db.Column(db.TIMESTAMP, default=db.func.now())
    tareas = db.relationship('Tarea', backref='usuario', lazy=True)  # Relación con tareas
    def __init__(self, *args, **kwargs):
        super(Usuario, self).__init__(*args, **kwargs)
        logging.info(f'Se creó un nuevo usuario: {self.usuario}')
    def check_password(self, contrasena):
        return self.contrasena == contrasena
    def __repr__(self):
        return f'<Usuario {self.usuario}>'

class Tarea(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(255), nullable=False)
    descripcion = db.Column(db.Text)
    frecuencia = db.Column(db.String(255), nullable=False)
    fecha_ejecucion = db.Column(db.DateTime)
    estado = db.Column(db.Enum('pendiente', 'en_progreso', 'completada', 'fallida'), nullable=False)
    fecha_creacion = db.Column(db.TIMESTAMP, default=db.func.now())
    usuario_id = db.Column(db.Integer, db.ForeignKey('usuario.id'), nullable=False)  # Clave foránea

    def __repr__(self):
        return f'<Tarea {self.nombre}>'

class Proceso(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(255), nullable=False)
    descripcion = db.Column(db.Text)
    estado = db.Column(db.Enum('activo', 'inactivo'), nullable=False)
    recursos_consumidos = db.Column(db.JSON)  # Para almacenar datos de recursos en formato JSON
    fecha_creacion = db.Column(db.TIMESTAMP, default=db.func.now())

    def __repr__(self):
        return f'<Proceso {self.nombre}>'
    
class Log(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    fecha = db.Column(db.TIMESTAMP, default=db.func.now())
    nivel = db.Column(db.Enum('info', 'warning', 'error'), nullable=False)
    mensaje = db.Column(db.Text, nullable=False)
    @classmethod
    def crear_log(cls, nivel, mensaje):
        try:
            nuevo_log = cls(nivel=nivel, mensaje=mensaje)
            db.session.add(nuevo_log)
            db.session.commit()
            logging.info(f'Se creó un nuevo log: {mensaje}')
            return nuevo_log
        except Exception as e:
            db.session.rollback()
            logging.error(f'Error al crear el log: {e}')
            return None

    def __repr__(self):
        return f'<Log {self.fecha}>'