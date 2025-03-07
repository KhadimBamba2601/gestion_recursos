from flask import Blueprint, render_template, redirect, url_for, request, flash, send_file, session, Response
from app import app, db, cache, mail  # Importar desde app
from app.models import Usuario, Notificacion, Tarea, ReporteRecurso, Proceso, Log
from flask_login import login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, EmailField, SubmitField, SelectField, TextAreaField, DateTimeLocalField
from wtforms.validators import DataRequired, Length, Email, EqualTo, Optional
from flask_mail import Message
from io import BytesIO, StringIO
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table
from reportlab.lib.styles import getSampleStyleSheet
from datetime import datetime
import psutil
import logging
import csv
import json
from sqlalchemy.exc import IntegrityError, OperationalError

# Configuración de logging
logging.basicConfig(level=logging.INFO)

# Formularios
class LoginForm(FlaskForm):
    nombre_usuario = StringField('Nombre de usuario', validators=[DataRequired()])
    contraseña = PasswordField('Contraseña', validators=[DataRequired()])
    submit = SubmitField('Iniciar sesión')

class RegistroForm(FlaskForm):
    nombre_usuario = StringField('Nombre de usuario', validators=[DataRequired(), Length(min=4, max=64)])
    correo = EmailField('Correo electrónico', validators=[DataRequired(), Email()])
    contraseña = PasswordField('Contraseña', validators=[DataRequired(), Length(min=8)])
    confirma_contraseña = PasswordField('Confirmar contraseña', validators=[DataRequired(), EqualTo('contraseña', message='Las contraseñas deben coincidir')])
    submit = SubmitField('Registrarse')

class EditarUsuarioForm(FlaskForm):
    nombre = StringField('Nombre de usuario', validators=[DataRequired(), Length(min=4, max=64)])
    email = EmailField('Correo electrónico', validators=[DataRequired(), Email()])
    contraseña = PasswordField('Contraseña (dejar en blanco para no cambiar)', validators=[Optional(), Length(min=8)])
    rol = SelectField('Rol', choices=[('usuario', 'Usuario'), ('administrador', 'Administrador')], validators=[DataRequired()])
    submit = SubmitField('Guardar cambios')

class ProcesoForm(FlaskForm):
    nombre = StringField('Nombre', validators=[DataRequired(), Length(max=255)])
    descripcion = TextAreaField('Descripción', validators=[Optional()])
    estado = SelectField('Estado', choices=[('activo', 'Activo'), ('inactivo', 'Inactivo')], validators=[DataRequired()])
    submit = SubmitField('Guardar')

class ReporteUsuariosForm(FlaskForm):
    nombre = StringField('Nombre', validators=[Optional()])
    rol = SelectField('Rol', choices=[('', ''), ('administrador', 'Administrador'), ('usuario', 'Usuario')], validators=[Optional()])
    submit = SubmitField('Generar Reporte')

class ReporteTareasForm(FlaskForm):
    nombre = StringField('Nombre', validators=[Optional()])
    usuario = StringField('Usuario', validators=[Optional()])
    submit = SubmitField('Generar Reporte')

class LogForm(FlaskForm):
    nivel = SelectField('Nivel', choices=[('info', 'Info'), ('warning', 'Warning'), ('error', 'Error')], validators=[DataRequired()])
    mensaje = TextAreaField('Mensaje', validators=[DataRequired()])
    submit = SubmitField('Crear')

class CrearTareaForm(FlaskForm):
    nombre = StringField('Nombre', validators=[DataRequired(), Length(max=255)])
    descripcion = TextAreaField('Descripción', validators=[Optional()])
    frecuencia = StringField('Frecuencia', validators=[DataRequired(), Length(max=255)])
    fecha_ejecucion = DateTimeLocalField('Fecha de ejecución', format='%Y-%m-%dT%H:%M', validators=[Optional()])
    submit = SubmitField('Crear')

class EditarTareaForm(FlaskForm):
    nombre = StringField('Nombre', validators=[DataRequired(), Length(max=255)])
    descripcion = TextAreaField('Descripción', validators=[Optional()])
    frecuencia = StringField('Frecuencia', validators=[DataRequired(), Length(max=255)])
    fecha_ejecucion = DateTimeLocalField('Fecha de ejecución', format='%Y-%m-%dT%H:%M', validators=[Optional()])
    submit = SubmitField('Guardar cambios')

class ContactForm(FlaskForm):
    destinatario = EmailField('Destinatario', validators=[DataRequired(), Email()])
    asunto = StringField('Asunto', validators=[DataRequired()])
    mensaje = TextAreaField('Mensaje', validators=[DataRequired()])
    submit = SubmitField('Enviar correo')

# Blueprints
auth_bp = Blueprint('auth', __name__)
usuario_bp = Blueprint('usuario', __name__)
proceso_bp = Blueprint('proceso', __name__)
tarea_bp = Blueprint('tarea', __name__)
log_bp = Blueprint('log', __name__)
reporte_bp = Blueprint('reporte', __name__)
email_bp = Blueprint('email', __name__)

from flask import jsonify

@app.route('/api/resources')
@login_required
def api_resources():
    recursos = obtener_recursos_sistema()
    return jsonify({
        'cpu': recursos['cpu'],
        'memory': recursos['memoria_porcentaje'],
        'storage': recursos['almacenamiento_porcentaje']
    })

# Funciones de recursos (de routes.py)
@cache.cached(timeout=30)
def obtener_recursos_sistema():
    cpu_porcentaje = psutil.cpu_percent(interval=1)
    memoria = psutil.virtual_memory()
    almacenamiento = psutil.disk_usage('/')
    return {
        'cpu': cpu_porcentaje,
        'memoria_total': memoria.total / (1024 ** 3),
        'memoria_usada': memoria.used / (1024 ** 3),
        'memoria_porcentaje': memoria.percent,
        'almacenamiento_total': almacenamiento.total / (1024 ** 3),
        'almacenamiento_usado': almacenamiento.used / (1024 ** 3),
        'almacenamiento_porcentaje': almacenamiento.percent
    }

def verificar_recursos():
    recursos = obtener_recursos_sistema()
    reporte = ReporteRecurso(
        cpu=recursos['cpu'],
        memoria_porcentaje=recursos['memoria_porcentaje'],
        almacenamiento_porcentaje=recursos['almacenamiento_porcentaje'],
        usuario_id=current_user.id if current_user.is_authenticated else None
    )
    db.session.add(reporte)
    if recursos['cpu'] > 80:
        notificacion = Notificacion(mensaje=f"Sobrecarga de CPU: {recursos['cpu']}%", usuario_id=current_user.id)
        db.session.add(notificacion)
    if recursos['memoria_porcentaje'] > 90:
        notificacion = Notificacion(mensaje=f"Uso de memoria elevado: {recursos['memoria_porcentaje']}%", usuario_id=current_user.id)
        db.session.add(notificacion)
    db.session.commit()

def respaldo_base_datos():
    with app.app_context():
        tarea = Tarea.query.filter_by(nombre='respaldo_db').first()
        if tarea:
            try:
                print("Realizando respaldo de la base de datos...")
                tarea.estado = 'completada'
                tarea.ultima_ejecucion = datetime.utcnow()
                db.session.commit()
                Log.crear_log('info', "Respaldo de base de datos completado.")
            except Exception as e:
                tarea.estado = 'fallida'
                notificacion = Notificacion(mensaje=f"Fallo en respaldo: {str(e)}", usuario_id=Usuario.query.filter_by(rol='administrador').first().id)
                db.session.add(notificacion)
                db.session.commit()
                Log.crear_log('error', f"Fallo en respaldo: {str(e)}")

def limpieza_logs():
    with app.app_context():
        tarea = Tarea.query.filter_by(nombre='limpieza_logs').first()
        if tarea:
            try:
                print("Limpiando logs...")
                tarea.estado = 'completada'
                tarea.ultima_ejecucion = datetime.utcnow()
                db.session.commit()
                Log.crear_log('info', "Limpieza de logs completada.")
            except Exception as e:
                tarea.estado = 'fallida'
                notificacion = Notificacion(mensaje=f"Fallo en limpieza: {str(e)}", usuario_id=Usuario.query.filter_by(rol='administrador').first().id)
                db.session.add(notificacion)
                db.session.commit()
                Log.crear_log('error', f"Fallo en limpieza: {str(e)}")

def inicializar_tareas():
    with app.app_context():
        admin = Usuario.query.filter_by(rol='administrador').first()
        if admin:
            if not Tarea.query.filter_by(nombre='respaldo_db').first():
                tarea = Tarea(nombre='respaldo_db', descripcion='Respaldo diario', frecuencia='diario', usuario_id=admin.id)
                db.session.add(tarea)
            if not Tarea.query.filter_by(nombre='limpieza_logs').first():
                tarea = Tarea(nombre='limpieza_logs', descripcion='Limpieza semanal', frecuencia='semanal', usuario_id=admin.id)
                db.session.add(tarea)
            db.session.commit()
            app.scheduler.add_job(respaldo_base_datos, 'interval', days=1, id='respaldo_db')
            app.scheduler.add_job(limpieza_logs, 'interval', weeks=1, id='limpieza_logs')

# Rutas de auth_bp
from flask import Blueprint, render_template, redirect, url_for, request, flash
from app import db, views, login_user
from app.models import Usuario
from flask_login import login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired

auth_bp = Blueprint('auth', __name__)


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        usuario = Usuario.query.filter_by(nombre_usuario=form.nombre_usuario.data).first()
        if usuario and usuario.verificar_contraseña(form.contraseña.data):
            login_user(usuario)
            flash('Inicio de sesión exitoso!', 'success')
            return redirect(url_for('panel_de_control'))
        flash('Credenciales inválidas', 'danger')
    return render_template('login.html', form=form)

@app.route('/')
def index():
    if current_user.is_authenticated:
        recursos = views.obtener_recursos_sistema()
        return render_template('index.html', 
                               cpu_usage=recursos['cpu'], 
                               memory_usage=recursos['memoria_porcentaje'], 
                               storage_usage=recursos['almacenamiento_porcentaje'])
    return render_template('index.html')

@auth_bp.route('/registro', methods=['GET', 'POST'])
def registro():
    form = RegistroForm()
    if form.validate_on_submit():
        if Usuario.query.filter_by(nombre_usuario=form.nombre_usuario.data).first():
            flash('Nombre de usuario ya existe.', 'danger')
            return render_template('registro.html', form=form)
        if Usuario.query.filter_by(correo=form.correo.data).first():
            flash('Correo ya existe.', 'danger')
            return render_template('registro.html', form=form)
        try:
            usuario = Usuario(nombre_usuario=form.nombre_usuario.data, correo=form.correo.data)
            usuario.establecer_contraseña(form.contraseña.data)
            db.session.add(usuario)
            db.session.commit()
            flash('¡Usuario registrado exitosamente!', 'success')
            Log.crear_log('info', f"Usuario {usuario.nombre_usuario} registrado.")
            return redirect(url_for('auth.login'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error al registrar usuario: {e}', 'danger')
            Log.crear_log('error', f"Error al registrar usuario: {e}")
    return render_template('registro.html', form=form)

@auth_bp.route('/logout')
@login_required
def logout():
    Log.crear_log('info', f"Usuario {current_user.nombre_usuario} cerró sesión.")
    logout_user()
    return redirect(url_for('index'))

# Rutas de usuario_bp
@usuario_bp.route('/usuarios')
@login_required
def listar_usuarios():
    if current_user.rol != 'administrador':
        flash('No tienes permiso para ver esta página.', 'danger')
        return redirect(url_for('panel_de_control'))
    usuarios = Usuario.query.all()
    return render_template('lista-usuario.html', usuarios=usuarios)

@usuario_bp.route('/usuarios/crear', methods=['GET', 'POST'])
@login_required
def crear_usuario():
    if current_user.rol != 'administrador':
        flash('No tienes permiso para crear usuarios.', 'danger')
        return redirect(url_for('panel_de_control'))
    form = RegistroForm()
    if form.validate_on_submit():
        try:
            if Usuario.query.filter_by(nombre_usuario=form.nombre.data).first():
                flash('Nombre de usuario ya existe.', 'danger')
                return render_template('crear-usuario.html', form=form)
            if Usuario.query.filter_by(correo=form.email.data).first():
                flash('Email ya existe.', 'danger')
                return render_template('crear-usuario.html', form=form)
            usuario = Usuario(nombre_usuario=form.nombre.data, correo=form.email.data, rol=form.rol.data)
            usuario.establecer_contraseña(form.contraseña.data)
            db.session.add(usuario)
            db.session.commit()
            flash('Usuario creado exitosamente', 'success')
            Log.crear_log('info', f"Usuario {usuario.nombre_usuario} creado por {current_user.nombre_usuario}")
            return redirect(url_for('usuario.listar_usuarios'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error al crear usuario: {e}', 'danger')
            Log.crear_log('error', f"Error al crear usuario: {e}")
    return render_template('crear-usuario.html', form=form)

@usuario_bp.route('/usuarios/editar/<int:id>', methods=['GET', 'POST'])
@login_required
def editar_usuario(id):
    if current_user.rol != 'administrador':
        flash('No tienes permiso para editar usuarios.', 'danger')
        return redirect(url_for('panel_de_control'))
    usuario = Usuario.query.get_or_404(id)
    form = EditarUsuarioForm(obj=usuario)
    if form.validate_on_submit():
        try:
            usuario.nombre_usuario = form.nombre.data
            usuario.correo = form.email.data
            usuario.rol = form.rol.data
            if form.contraseña.data:
                usuario.establecer_contraseña(form.contraseña.data)
            db.session.commit()
            flash('Usuario actualizado exitosamente', 'success')
            Log.crear_log('info', f"Usuario {usuario.nombre_usuario} actualizado por {current_user.nombre_usuario}")
            return redirect(url_for('usuario.listar_usuarios'))
        except IntegrityError as e:
            db.session.rollback()
            flash('El nombre de usuario o correo ya está en uso.', 'danger')
            Log.crear_log('error', f"Error al actualizar usuario (IntegrityError): {e}")
        except Exception as e:
            db.session.rollback()
            flash(f'Error al actualizar usuario: {e}', 'danger')
            Log.crear_log('error', f"Error al actualizar usuario: {e}")
    return render_template('editar-usuario.html', usuario=usuario, form=form)

@usuario_bp.route('/usuarios/eliminar/<int:id>', methods=['POST'])
@login_required
def eliminar_usuario(id):
    if current_user.rol != 'administrador':
        flash('No tienes permiso para eliminar usuarios.', 'danger')
        return redirect(url_for('panel_de_control'))
    usuario = Usuario.query.get_or_404(id)
    try:
        db.session.delete(usuario)
        db.session.commit()
        flash('Usuario eliminado exitosamente', 'success')
        Log.crear_log('info', f"Usuario {usuario.nombre_usuario} eliminado por {current_user.nombre_usuario}")
    except Exception as e:
        db.session.rollback()
        flash(f'Error al eliminar usuario: {e}', 'danger')
        Log.crear_log('error', f"Error al eliminar usuario: {e}")
    return redirect(url_for('usuario.listar_usuarios'))

# Rutas generales
@app.route('/')
def index():
    if current_user.is_authenticated:
        recursos = obtener_recursos_sistema()
        return render_template('index.html', 
                               cpu_usage=recursos['cpu'], 
                               memory_usage=recursos['memoria_porcentaje'], 
                               storage_usage=recursos['almacenamiento_porcentaje'])
    return render_template('index.html')

@app.route('/panel_de_control')
@login_required
def panel_de_control():
    try:
        recursos = obtener_recursos_sistema()
        tareas = Tarea.query.filter_by(usuario_id=current_user.id).all()
        notificaciones = Notificacion.query.filter_by(usuario_id=current_user.id, leida=False).all()
        cpu_data = json.dumps([float(recursos['cpu']), 100 - float(recursos['cpu'])])
        memory_data = json.dumps([float(recursos['memoria_porcentaje']), 100 - float(recursos['memoria_porcentaje'])])
        storage_data = json.dumps([float(recursos['almacenamiento_porcentaje']), 100 - float(recursos['almacenamiento_porcentaje'])])
        return render_template('panel_de_control.html',
                               cpu_usage=recursos['cpu'],
                               memory_usage=recursos['memoria_porcentaje'],
                               storage_usage=recursos['almacenamiento_porcentaje'],
                               cpu_data=cpu_data,
                               memory_data=memory_data,
                               storage_data=storage_data,
                               tareas=tareas,
                               notificaciones=notificaciones)
    except Exception as e:
        flash(f"Error al obtener información del sistema: {e}", "danger")
        Log.crear_log('error', f"Error en Panel de Control: {e}")
        return render_template('panel_de_control.html', tareas=[], notificaciones=[])

# Rutas de proceso_bp
@proceso_bp.route('/', methods=['GET', 'POST'])
@login_required
def listar_procesos():
    if current_user.rol != 'administrador':
        flash('No tienes permiso para ver esta página.', 'danger')
        return redirect(url_for('panel_de_control'))
    form = ProcesoForm()
    if form.validate_on_submit():
        try:
            proceso = Proceso(
                nombre=form.nombre.data,
                descripcion=form.descripcion.data,
                estado=form.estado.data
            )
            db.session.add(proceso)
            db.session.commit()
            flash(f'Proceso {proceso.nombre} creado.', 'success')
            Log.crear_log('info', f"Proceso {proceso.nombre} creado por {current_user.nombre_usuario}")
            return redirect(url_for('proceso.listar_procesos'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error al crear proceso: {e}', 'danger')
            Log.crear_log('error', f"Error al crear proceso: {e}")
    procesos = Proceso.query.all()
    return render_template('lista-procesos.html', procesos=procesos, form=form)

@proceso_bp.route('/<int:proceso_id>', methods=['GET', 'POST'])
@login_required
def detalles_proceso(proceso_id):
    if current_user.rol != 'administrador':
        flash('No tienes permiso para ver esta página.', 'danger')
        return redirect(url_for('panel_de_control'))
    proceso = Proceso.query.get_or_404(proceso_id)
    form = ProcesoForm(obj=proceso)
    if form.validate_on_submit():
        try:
            proceso.nombre = form.nombre.data
            proceso.descripcion = form.descripcion.data
            proceso.estado = form.estado.data
            db.session.commit()
            flash(f'Proceso {proceso.nombre} modificado.', 'success')
            Log.crear_log('info', f"Proceso {proceso.nombre} modificado por {current_user.nombre_usuario}")
            return redirect(url_for('proceso.detalles_proceso', proceso_id=proceso_id))
        except Exception as e:
            db.session.rollback()
            flash(f'Error al modificar proceso: {e}', 'danger')
            Log.crear_log('error', f"Error al modificar proceso: {e}")
    proceso_sistema = None
    try:
        for proc in psutil.process_iter(['name', 'pid', 'cpu_percent', 'memory_percent']):
            if proc.info['name'] == proceso.nombre:
                proceso_sistema = proc.info
                break
    except psutil.NoSuchProcess:
        flash(f'No se encontró el proceso {proceso.nombre} en el sistema.', 'warning')
    except Exception as e:
        flash(f'Error al obtener información del proceso: {e}', 'danger')
        Log.crear_log('error', f"Error al obtener info de proceso: {e}")
    return render_template('detalle-procesos.html', proceso=proceso, proceso_sistema=proceso_sistema, form=form)

@proceso_bp.route('/iniciar/<int:proceso_id>', methods=['POST'])
@login_required
def iniciar_proceso(proceso_id):
    if current_user.rol != 'administrador':
        flash('No tienes permiso para esta acción.', 'danger')
        return redirect(url_for('panel_de_control'))
    proceso = Proceso.query.get_or_404(proceso_id)
    if proceso.estado == 'activo':
        flash(f'El proceso {proceso.nombre} ya está activo.', 'info')
    else:
        try:
            proceso.estado = 'activo'
            db.session.commit()
            flash(f'Proceso {proceso.nombre} iniciado.', 'success')
            Log.crear_log('info', f"Proceso {proceso.nombre} iniciado por {current_user.nombre_usuario}")
        except Exception as e:
            db.session.rollback()
            flash(f'Error al iniciar el proceso: {e}', 'danger')
            Log.crear_log('error', f"Error al iniciar proceso: {e}")
    return redirect(url_for('proceso.detalles_proceso', proceso_id=proceso_id))

@proceso_bp.route('/detener/<int:proceso_id>', methods=['POST'])
@login_required
def detener_proceso(proceso_id):
    if current_user.rol != 'administrador':
        flash('No tienes permiso para esta acción.', 'danger')
        return redirect(url_for('panel_de_control'))
    proceso = Proceso.query.get_or_404(proceso_id)
    if proceso.estado == 'inactivo':
        flash(f'El proceso {proceso.nombre} ya está inactivo.', 'info')
    else:
        try:
            proceso.estado = 'inactivo'
            db.session.commit()
            flash(f'Proceso {proceso.nombre} detenido.', 'success')
            Log.crear_log('info', f"Proceso {proceso.nombre} detenido por {current_user.nombre_usuario}")
        except Exception as e:
            db.session.rollback()
            flash(f'Error al detener el proceso: {e}', 'danger')
            Log.crear_log('error', f"Error al detener proceso: {e}")
    return redirect(url_for('proceso.detalles_proceso', proceso_id=proceso_id))

@proceso_bp.route('/monitor')
@login_required
def monitor_procesos():
    if current_user.rol != 'administrador':
        flash('No tienes permiso para ver esta página.', 'danger')
        return redirect(url_for('panel_de_control'))
    procesos_sistema = []
    try:
        for proc in psutil.process_iter(['name', 'status', 'cpu_percent', 'memory_percent', 'pid']):
            procesos_sistema.append({
                'nombre': proc.info['name'],
                'estado': proc.info['status'],
                'cpu_uso': proc.info['cpu_percent'],
                'memoria_uso': proc.info['memory_percent'],
                'pid': proc.info['pid']
            })
    except Exception as e:
        flash(f'Error al obtener la lista de procesos del sistema: {e}', 'danger')
        Log.crear_log('error', f"Error al monitorizar procesos: {e}")
    return render_template('detalle-procesos.html', procesos_sistema=procesos_sistema)

# Rutas de tarea_bp
@tarea_bp.route('/tareas')
@login_required
def listar_tareas():
    tareas = Tarea.query.filter_by(usuario_id=current_user.id).all()
    return render_template('lista-tarea.html', tareas=tareas)

@tarea_bp.route('/tareas/crear', methods=['GET', 'POST'])
@login_required
def crear_tarea():
    form = CrearTareaForm()
    if form.validate_on_submit():
        try:
            nueva_tarea = Tarea(
                nombre=form.nombre.data,
                descripcion=form.descripcion.data,
                frecuencia=form.frecuencia.data,
                fecha_ejecucion=form.fecha_ejecucion.data,
                usuario_id=current_user.id
            )
            db.session.add(nueva_tarea)
            db.session.commit()
            flash('Tarea creada con éxito.', 'success')
            Log.crear_log('info', f"Tarea {nueva_tarea.nombre} creada por {current_user.nombre_usuario}")
            return redirect(url_for('tarea.listar_tareas'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error al crear tarea: {e}', 'danger')
            Log.crear_log('error', f"Error al crear tarea: {e}")
    return render_template('crear-tarea.html', form=form)

@tarea_bp.route('/tareas/editar/<int:tarea_id>', methods=['GET', 'POST'])
@login_required
def editar_tarea(tarea_id):
    tarea = Tarea.query.get_or_404(tarea_id)
    if tarea.usuario_id != current_user.id and current_user.rol != 'administrador':
        flash('No tienes permiso para editar esta tarea.', 'danger')
        return redirect(url_for('tarea.listar_tareas'))
    form = EditarTareaForm(obj=tarea)
    if form.validate_on_submit():
        try:
            tarea.nombre = form.nombre.data
            tarea.descripcion = form.descripcion.data
            tarea.frecuencia = form.frecuencia.data
            tarea.fecha_ejecucion = form.fecha_ejecucion.data
            db.session.commit()
            flash('Tarea actualizada con éxito.', 'success')
            Log.crear_log('info', f"Tarea {tarea.nombre} actualizada por {current_user.nombre_usuario}")
            return redirect(url_for('tarea.listar_tareas'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error al actualizar tarea: {e}', 'danger')
            Log.crear_log('error', f"Error al actualizar tarea: {e}")
    return render_template('editar-tarea.html', tarea=tarea, form=form)

@tarea_bp.route('/tareas/eliminar/<int:tarea_id>', methods=['POST'])
@login_required
def eliminar_tarea(tarea_id):
    tarea = Tarea.query.get_or_404(tarea_id)
    if tarea.usuario_id != current_user.id and current_user.rol != 'administrador':
        flash('No tienes permiso para eliminar esta tarea.', 'danger')
        return redirect(url_for('tarea.listar_tareas'))
    try:
        db.session.delete(tarea)
        db.session.commit()
        flash('Tarea eliminada con éxito.', 'success')
        Log.crear_log('info', f"Tarea {tarea.nombre} eliminada por {current_user.nombre_usuario}")
    except Exception as e:
        db.session.rollback()
        flash(f'Error al eliminar tarea: {e}', 'danger')
        Log.crear_log('error', f"Error al eliminar tarea: {e}")
    return redirect(url_for('tarea.listar_tareas'))

# Rutas de log_bp
@log_bp.route('/logs')
@login_required
def listar_logs():
    try:
        logs = Log.query.order_by(Log.fecha.desc()).all()
        return render_template('lista-log.html', logs=logs)
    except Exception as e:
        flash(f'Error al obtener logs: {e}', 'danger')
        Log.crear_log('error', f"Error al obtener logs: {e}")
        return render_template('lista-log.html', logs=[])

@log_bp.route('/logs/crear', methods=['GET', 'POST'])
@login_required
def crear_log():
    form = LogForm()
    if form.validate_on_submit():
        try:
            nuevo_log = Log(nivel=form.nivel.data, mensaje=form.mensaje.data)
            db.session.add(nuevo_log)
            db.session.commit()
            flash('Log creado con éxito.', 'success')
            Log.crear_log('info', f"Log creado por {current_user.nombre_usuario}: {form.mensaje.data}")
            return redirect(url_for('log.listar_logs'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error al crear log: {e}', 'danger')
            Log.crear_log('error', f"Error al crear log: {e}")
    return render_template('crear-log.html', form=form)

@log_bp.route('/logs/eliminar/<int:log_id>', methods=['POST'])
@login_required
def eliminar_log(log_id):
    if current_user.rol != 'administrador':
        flash('No tienes permiso para eliminar logs.', 'danger')
        return redirect(url_for('log.listar_logs'))
    log_a_eliminar = Log.query.get_or_404(log_id)
    try:
        db.session.delete(log_a_eliminar)
        db.session.commit()
        flash('Log eliminado con éxito.', 'success')
        Log.crear_log('info', f"Log eliminado por {current_user.nombre_usuario}")
    except Exception as e:
        db.session.rollback()
        flash(f'Error al eliminar log: {e}', 'danger')
        Log.crear_log('error', f"Error al eliminar log: {e}")
    return redirect(url_for('log.listar_logs'))

# Rutas de reporte_bp
@reporte_bp.route('/reportes', methods=['GET', 'POST'])
@login_required
def panel_de_control_reportes():
    if current_user.rol != 'administrador':
        flash('No tienes permiso para ver esta página.', 'danger')
        return redirect(url_for('panel_de_control'))
    usuarios_form = ReporteUsuariosForm()
    tareas_form = ReporteTareasForm()
    usuarios_count = Usuario.query.count()
    procesos_count = Proceso.query.count()
    tareas_count = Tarea.query.count()
    return render_template('panel_de_control-reportes.html',
                           usuarios_count=usuarios_count,
                           procesos_count=procesos_count,
                           tareas_count=tareas_count,
                           usuarios_form=usuarios_form,
                           tareas_form=tareas_form)

@reporte_bp.route('/reportes/usuarios/pdf', methods=['POST'])
@login_required
def reporte_usuarios_pdf():
    if current_user.rol != 'administrador':
        flash('No tienes permiso para generar reportes.', 'danger')
        return redirect(url_for('panel_de_control'))
    usuarios_form = ReporteUsuariosForm(request.form)
    if usuarios_form.validate_on_submit():
        try:
            nombre_filtro = usuarios_form.nombre.data
            rol_filtro = usuarios_form.rol.data
            usuarios = Usuario.query.filter(
                Usuario.nombre_usuario.like(f"%{nombre_filtro}%") if nombre_filtro else True,
                Usuario.rol == rol_filtro if rol_filtro else True
            ).all()
            buffer = BytesIO()
            p = canvas.Canvas(buffer, pagesize=letter)
            p.setFont("Helvetica-Bold", 16)
            p.drawString(inch, 10.5 * inch, "Reporte de Usuarios")
            p.setFont("Helvetica", 12)
            p.drawString(inch, 10 * inch, f"Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            y_pos = 9.5 * inch
            for usuario in usuarios:
                p.drawString(inch, y_pos, f"Nombre: {usuario.nombre_usuario}")
                p.drawString(3 * inch, y_pos, f"Correo: {usuario.correo}")
                p.drawString(5 * inch, y_pos, f"Rol: {usuario.rol}")
                y_pos -= 0.5 * inch
            p.showPage()
            p.save()
            buffer.seek(0)
            return send_file(buffer, mimetype='application/pdf', download_name='reporte_usuarios.pdf', as_attachment=True)
        except Exception as e:
            flash(f"Error al generar reporte: {e}", "danger")
            Log.crear_log('error', f"Error al generar reporte de usuarios: {e}")
            return redirect(url_for('reporte.panel_de_control_reportes'))
    flash("Error en el formulario", "danger")
    return redirect(url_for('reporte.panel_de_control_reportes'))

@reporte_bp.route('/reportes/tareas/csv', methods=['POST'])
@login_required
def reporte_tareas_csv():
    if current_user.rol != 'administrador':
        flash('No tienes permiso para generar reportes.', 'danger')
        return redirect(url_for('panel_de_control'))
    tareas_form = ReporteTareasForm(request.form)
    if tareas_form.validate_on_submit():
        try:
            nombre_filtro = tareas_form.nombre.data
            usuario_filtro = tareas_form.usuario.data
            tareas = Tarea.query.filter(
                Tarea.nombre.like(f"%{nombre_filtro}%") if nombre_filtro else True,
                Tarea.usuario.has(nombre_usuario=usuario_filtro) if usuario_filtro else True
            ).all()
            output = StringIO()
            writer = csv.writer(output)
            writer.writerow(['Nombre', 'Descripción', 'Frecuencia', 'Fecha de Ejecución', 'Usuario'])
            for tarea in tareas:
                writer.writerow([tarea.nombre, tarea.descripcion, tarea.frecuencia, tarea.fecha_ejecucion, tarea.usuario.nombre_usuario])
            output.seek(0)
            return Response(output.getvalue(), mimetype='text/csv', headers={"Content-Disposition": "attachment;filename=reporte_tareas.csv"})
        except Exception as e:
            flash(f"Error al generar reporte: {e}", "danger")
            Log.crear_log('error', f"Error al generar reporte de tareas: {e}")
            return redirect(url_for('reporte.panel_de_control_reportes'))
    flash("Error en el formulario", "danger")
    return redirect(url_for('reporte.panel_de_control_reportes'))

@reporte_bp.route('/generar_reporte', methods=['GET', 'POST'])
@login_required
def generar_reporte():
    if current_user.rol != 'administrador':
        flash('No tienes permiso para generar reportes.', 'danger')
        return redirect(url_for('panel_de_control'))
    if request.method == 'POST':
        tipo_reporte = request.form.get('tipo_reporte')
        formato_reporte = request.form.get('formato_reporte')
        fecha_inicio_str = request.form.get('fecha_inicio')
        fecha_fin_str = request.form.get('fecha_fin')
        try:
            fecha_inicio = datetime.strptime(fecha_inicio_str, '%Y-%m-%d').date()
            fecha_fin = datetime.strptime(fecha_fin_str, '%Y-%m-%d').date()
            if tipo_reporte == 'rendimiento_sistema':
                datos_reporte = obtener_datos_rendimiento(fecha_inicio, fecha_fin)
                titulo_reporte = "Reporte de Rendimiento del Sistema"
            elif tipo_reporte == 'tiempos_respuesta':
                datos_reporte = obtener_datos_tiempos_respuesta(fecha_inicio, fecha_fin)
                titulo_reporte = "Reporte de Tiempos de Respuesta"
            elif tipo_reporte == 'utilizacion_recursos':
                datos_reporte = obtener_datos_utilizacion_recursos(fecha_inicio, fecha_fin)
                titulo_reporte = "Reporte de Utilización de Recursos"
            else:
                flash("Tipo de reporte no válido.", "danger")
                return redirect(url_for('reporte.generar_reporte'))
            if formato_reporte == 'pdf' or formato_reporte == 'csv':
                session['datos_reporte'] = datos_reporte
                session['titulo_reporte'] = titulo_reporte
                session['formato_reporte'] = formato_reporte
                session['tipo_reporte'] = tipo_reporte
                session['fecha_inicio'] = fecha_inicio_str
                session['fecha_fin'] = fecha_fin_str
                return redirect(url_for('reporte.detalle_reporte'))
            else:
                flash("Formato de reporte no válido.", "danger")
                return redirect(url_for('reporte.generar_reporte'))
        except ValueError:
            flash("Formato de fecha incorrecto. Debe ser YYYY-MM-DD.", "danger")
            return redirect(url_for('reporte.generar_reporte'))
        except Exception as e:
            flash(f"Error al generar el reporte: {e}", "danger")
            Log.crear_log('error', f"Error al generar reporte: {e}")
            return redirect(url_for('reporte.generar_reporte'))
    return render_template('generar_reporte.html')

@reporte_bp.route('/detalle_reporte')
@login_required
def detalle_reporte():
    if current_user.rol != 'administrador':
        flash('No tienes permiso para ver esta página.', 'danger')
        return redirect(url_for('panel_de_control'))
    datos_reporte = session.get('datos_reporte')
    titulo_reporte = session.get('titulo_reporte')
    formato_reporte = session.get('formato_reporte')
    tipo_reporte = session.get('tipo_reporte')
    fecha_inicio = session.get('fecha_inicio')
    fecha_fin = session.get('fecha_fin')
    if not datos_reporte:
        flash("No hay datos de reporte disponibles.", "warning")
        return redirect(url_for('reporte.generar_reporte'))
    if formato_reporte == 'pdf':
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        styles = getSampleStyleSheet()
        elements = []
        elements.append(Paragraph(titulo_reporte, styles['Title']))
        elements.append(Spacer(1, 12))
        elements.append(Paragraph(f"Generado el: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
        elements.append(Spacer(1, 12))
        data = [list(datos_reporte[0].keys())] if datos_reporte else []
        for dato in datos_reporte:
            data.append([str(v) for v in dato.values()])
        table = Table(data)
        table.setStyle([('GRID', (0, 0), (-1, -1), 1, 'black'), ('ALIGN', (0, 0), (-1, -1), 'CENTER')])
        elements.append(table)
        doc.build(elements)
        buffer.seek(0)
        return Response(buffer.getvalue(), mimetype='application/pdf', headers={"Content-Disposition": f"attachment;filename={titulo_reporte}.pdf"})
    elif formato_reporte == 'csv':
        output = StringIO()
        writer = csv.writer(output)
        if datos_reporte:
            writer.writerow(datos_reporte[0].keys())
            for row in datos_reporte:
                writer.writerow(row.values())
        output.seek(0)
        return Response(output.getvalue(), mimetype='text/csv', headers={"Content-Disposition": f"attachment;filename={titulo_reporte}.csv"})
    return render_template('detalle-reporte.html', datos_reporte=datos_reporte, titulo_reporte=titulo_reporte, tipo_reporte=tipo_reporte, fecha_inicio=fecha_inicio, fecha_fin=fecha_fin)

# Funciones para obtener datos de reportes
def obtener_datos_rendimiento(fecha_inicio, fecha_fin):
    try:
        reportes = ReporteRecurso.query.filter(ReporteRecurso.fecha >= fecha_inicio, ReporteRecurso.fecha <= fecha_fin).all()
        return [{'fecha': r.fecha, 'cpu': r.cpu, 'memoria': r.memoria_porcentaje, 'almacenamiento': r.almacenamiento_porcentaje} for r in reportes]
    except Exception as e:
        Log.crear_log('error', f"Error al obtener datos de rendimiento: {e}")
        return []

def obtener_datos_tiempos_respuesta(fecha_inicio, fecha_fin):
    try:
        tareas = Tarea.query.filter(Tarea.fecha_ejecucion >= fecha_inicio, Tarea.fecha_ejecucion <= fecha_fin).all()
        return [{'fecha': t.fecha_ejecucion, 'tarea': t.nombre, 'estado': t.estado} for t in tareas if t.fecha_ejecucion]
    except Exception as e:
        Log.crear_log('error', f"Error al obtener datos de tiempos de respuesta: {e}")
        return []

def obtener_datos_utilizacion_recursos(fecha_inicio, fecha_fin):
    try:
        reportes = ReporteRecurso.query.filter(ReporteRecurso.fecha >= fecha_inicio, ReporteRecurso.fecha <= fecha_fin).all()
        return [{'fecha': r.fecha, 'cpu': r.cpu, 'memoria': r.memoria_porcentaje, 'almacenamiento': r.almacenamiento_porcentaje} for r in reportes]
    except Exception as e:
        Log.crear_log('error', f"Error al obtener datos de utilización de recursos: {e}")
        return []

# Rutas de email_bp
@email_bp.route('/enviar_logs', methods=['GET', 'POST'])
@login_required
def enviar_logs():
    if current_user.rol != 'administrador':
        flash('No tienes permiso para enviar logs.', 'danger')
        return redirect(url_for('panel_de_control'))
    form = ContactForm()
    if form.validate_on_submit():
        try:
            logs = Log.query.order_by(Log.fecha.desc()).all()
            mensaje = "\n".join([f"{log.fecha} - {log.nivel}: {log.mensaje}" for log in logs])
            msg = Message(form.asunto.data, recipients=[form.destinatario.data], body=mensaje)
            mail.send(msg)
            flash('Logs enviados por correo con éxito.', 'success')
            Log.crear_log('info', f"Logs enviados a {form.destinatario.data} por {current_user.nombre_usuario}")
            return redirect(url_for('log.listar_logs'))
        except Exception as e:
            flash(f'Error al enviar logs por correo: {e}', 'danger')
            Log.crear_log('error', f"Error al enviar logs por correo: {e}")
    return render_template('email/enviar-correo.html', form=form)

auth_bp = Blueprint('auth', __name__)
usuario_bp = Blueprint('usuario', __name__)
proceso_bp = Blueprint('proceso', __name__)
tarea_bp = Blueprint('tarea', __name__)
log_bp = Blueprint('log', __name__)
reporte_bp = Blueprint('reporte', __name__)
email_bp = Blueprint('email', __name__)