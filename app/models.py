from app import db
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from datetime import datetime

class Usuario(UserMixin, db.Model):
    __tablename__ = 'usuarios'
    id = db.Column(db.Integer, primary_key=True)
    nombre_usuario = db.Column(db.String(50), unique=True, nullable=False)
    correo = db.Column(db.String(120), unique=True, nullable=False)
    contraseña_hash = db.Column(db.String(256), nullable=False)
    rol = db.Column(db.String(20), default='usuario')
    nombre = db.Column(db.String(50))
    apellido = db.Column(db.String(50))
    tareas = db.relationship('Tarea', backref='usuario', lazy=True)
    reportes = db.relationship('ReporteRecurso', backref='usuario', lazy=True)
    notificaciones = db.relationship('Notificacion', backref='usuario', lazy=True)

    def establecer_contraseña(self, contraseña):
        self.contraseña_hash = generate_password_hash(contraseña)

    def verificar_contraseña(self, contraseña):
        return check_password_hash(self.contraseña_hash, contraseña)

class Tarea(db.Model):
    __tablename__ = 'tareas'
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(50), nullable=False)
    descripcion = db.Column(db.String(200))
    frecuencia = db.Column(db.String(20), nullable=False)
    hora_ejecucion = db.Column(db.String(5), nullable=False)
    estado = db.Column(db.String(20), default='pendiente')
    ultima_ejecucion = db.Column(db.DateTime)
    usuario_id = db.Column(db.Integer, db.ForeignKey('usuarios.id'), nullable=False)

class ReporteRecurso(db.Model):
    __tablename__ = 'reportes_recursos'
    id = db.Column(db.Integer, primary_key=True)
    cpu = db.Column(db.Float, nullable=False)
    memoria_porcentaje = db.Column(db.Float, nullable=False)
    almacenamiento_porcentaje = db.Column(db.Float, nullable=False)
    tiempo_respuesta = db.Column(db.Float, nullable=False, default=0.0)  
    fecha = db.Column(db.DateTime, default=datetime.utcnow)
    usuario_id = db.Column(db.Integer, db.ForeignKey('usuarios.id'), nullable=False)

class Notificacion(db.Model):
    __tablename__ = 'notificaciones'
    id = db.Column(db.Integer, primary_key=True)
    mensaje = db.Column(db.String(200), nullable=False)
    fecha = db.Column(db.DateTime, default=datetime.utcnow)
    leida = db.Column(db.Boolean, default=False)
    usuario_id = db.Column(db.Integer, db.ForeignKey('usuarios.id'), nullable=False)