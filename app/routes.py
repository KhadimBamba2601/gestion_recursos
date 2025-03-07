import importlib
import app.utils
importlib.reload(app.utils)
from flask import render_template, redirect, url_for, request, flash, Response
from app import app, db, cache, login_user, logout_user, login_required, current_user, scheduler
from app.models import Usuario, Notificacion, Tarea, ReporteRecurso
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, SelectField
from wtforms.validators import DataRequired, Length
import psutil, csv, io
from datetime import datetime, timedelta
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table
from app.utils import obtener_recursos_sistema

# Formularios
class FormularioLogin(FlaskForm):
    nombre_usuario = StringField('Nombre de usuario', validators=[DataRequired()])
    contraseña = PasswordField('Contraseña', validators=[DataRequired()])
    submit = SubmitField('Iniciar Sesión')

class FormularioRegistro(FlaskForm):
    nombre_usuario = StringField('Nombre de usuario', validators=[DataRequired(), Length(min=4, max=64)])
    correo = StringField('Correo', validators=[DataRequired()])
    contraseña = PasswordField('Contraseña', validators=[DataRequired(), Length(min=8)])
    submit = SubmitField('Registrarse')

class FormularioTarea(FlaskForm):
    tareas_predefinidas = [
        ('monitoreo_sistema', 'Monitoreo del sistema'),
        ('actualizacion_datos', 'Actualización de datos'),
        ('envio_notificaciones', 'Envío de notificaciones'),
        ('procesamiento_tareas', 'Procesamiento de tareas'),
        ('generacion_reportes', 'Generación de reportes'),
        ('sincronizacion_datos', 'Sincronización de datos'),
        ('respaldo_db', 'Respaldo diario'),
        ('limpieza_logs', 'Limpieza semanal'),
        ('actualizaciones_software', 'Actualizaciones de software'),
    ]
    nombre = SelectField('Tarea', choices=tareas_predefinidas, validators=[DataRequired()])
    frecuencia = SelectField('Frecuencia', choices=[('unica', 'Única'), ('diario', 'Diario'), ('semanal', 'Semanal'), ('mensual', 'Mensual')], validators=[DataRequired()])
    hora_ejecucion = StringField('Hora de Ejecución (HH:MM)', validators=[DataRequired()])
    submit = SubmitField('Guardar')

# Formulario para crear usuarios (agregar justo después de FormularioTarea)
class FormularioCrearUsuario(FlaskForm):
    nombre_usuario = StringField('Nombre de usuario', validators=[DataRequired(), Length(min=4, max=64)])
    correo = StringField('Correo', validators=[DataRequired()])
    contraseña = PasswordField('Contraseña', validators=[DataRequired(), Length(min=8)])
    rol = SelectField('Rol', choices=[('usuario', 'Usuario'), ('administrador', 'Administrador')], validators=[DataRequired()])
    nombre = StringField('Nombre', validators=[Length(max=64)])
    apellido = StringField('Apellido', validators=[Length(max=64)])
    submit = SubmitField('Crear Usuario')

class FormularioEditarUsuario(FlaskForm):
    nombre_usuario = StringField('Nombre de usuario', validators=[DataRequired(), Length(min=4, max=64)])
    correo = StringField('Correo', validators=[DataRequired()])
    rol = SelectField('Rol', choices=[('usuario', 'Usuario'), ('administrador', 'Administrador')], validators=[DataRequired()])
    nombre = StringField('Nombre', validators=[Length(max=64)])
    apellido = StringField('Apellido', validators=[Length(max=64)])
    submit = SubmitField('Actualizar Usuario')

# Ruta existente para listar usuarios
@app.route('/usuarios')
@login_required
def listar_usuarios():
    if current_user.rol != 'administrador':
        flash('Acceso denegado: Solo los administradores pueden ver la lista de usuarios.', 'danger')
        return redirect(url_for('panel_de_control'))
    usuarios = Usuario.query.all()
    return render_template('lista-usuario.html', usuarios=usuarios)

# Nueva ruta para crear usuarios
@app.route('/crear_usuario', methods=['GET', 'POST'])
@login_required
def crear_usuario():
    if current_user.rol != 'administrador':
        flash('Acceso denegado: Solo los administradores pueden crear usuarios.', 'danger')
        return redirect(url_for('panel_de_control'))
    form = FormularioCrearUsuario()
    if form.validate_on_submit():
        # Verificar si el nombre de usuario o correo ya existen
        if Usuario.query.filter_by(nombre_usuario=form.nombre_usuario.data).first():
            flash('El nombre de usuario ya existe.', 'danger')
            return render_template('crear-usuario.html', form=form)
        if Usuario.query.filter_by(correo=form.correo.data).first():
            flash('El correo ya está registrado.', 'danger')
            return render_template('crear-usuario.html', form=form)
        # Crear nuevo usuario
        nuevo_usuario = Usuario(
            nombre_usuario=form.nombre_usuario.data,
            correo=form.correo.data,
            rol=form.rol.data,
            nombre=form.nombre.data,
            apellido=form.apellido.data
        )
        nuevo_usuario.establecer_contraseña(form.contraseña.data)
        db.session.add(nuevo_usuario)
        db.session.commit()
        flash('Usuario creado exitosamente.', 'success')
        return redirect(url_for('listar_usuarios'))
    return render_template('crear-usuario.html', form=form)

@app.route('/editar_usuario/<int:id>', methods=['GET', 'POST'])
@login_required
def editar_usuario(id):
    if current_user.rol != 'administrador':
        flash('Acceso denegado: Solo los administradores pueden editar usuarios.', 'danger')
        return redirect(url_for('panel_de_control'))
    usuario = Usuario.query.get_or_404(id)
    form = FormularioEditarUsuario(obj=usuario)
    if form.validate_on_submit():
        # Verificar si el nombre de usuario o correo ya existen (excluyendo al usuario actual)
        usuario_existente = Usuario.query.filter_by(nombre_usuario=form.nombre_usuario.data).first()
        if usuario_existente and usuario_existente.id != usuario.id:
            flash('El nombre de usuario ya existe.', 'danger')
            return render_template('editar-usuario.html', form=form, usuario=usuario)
        correo_existente = Usuario.query.filter_by(correo=form.correo.data).first()
        if correo_existente and correo_existente.id != usuario.id:
            flash('El correo ya está registrado.', 'danger')
            return render_template('editar-usuario.html', form=form, usuario=usuario)
        # Actualizar los datos del usuario
        usuario.nombre_usuario = form.nombre_usuario.data
        usuario.correo = form.correo.data
        usuario.rol = form.rol.data
        usuario.nombre = form.nombre.data
        usuario.apellido = form.apellido.data
        db.session.commit()
        flash('Usuario actualizado exitosamente.', 'success')
        return redirect(url_for('listar_usuarios'))
    return render_template('editar-usuario.html', form=form, usuario=usuario)

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

def monitoreo_sistema():
    with app.app_context():
        tarea = Tarea.query.filter_by(nombre='monitoreo_sistema').first()
        if tarea:
            try:
                recursos = obtener_recursos_sistema()
                reporte = ReporteRecurso(cpu=recursos['cpu'], memoria_porcentaje=recursos['memoria_porcentaje'], almacenamiento_porcentaje=recursos['almacenamiento_porcentaje'])
                db.session.add(reporte)
                tarea.estado = 'completada'
                tarea.ultima_ejecucion = datetime.utcnow()
                db.session.commit()
            except Exception as e:
                tarea.estado = 'fallida'
                db.session.add(Notificacion(mensaje=f"Fallo en monitoreo: {str(e)}", usuario_id=Usuario.query.filter_by(rol='administrador').first().id))
                db.session.commit()

def actualizacion_datos():
    with app.app_context():
        tarea = Tarea.query.filter_by(nombre='actualizacion_datos').first()
        if tarea:
            try:
                print("Actualizando datos del sistema...")
                tarea.estado = 'completada'
                tarea.ultima_ejecucion = datetime.utcnow()
                db.session.commit()
            except Exception as e:
                tarea.estado = 'fallida'
                db.session.add(Notificacion(mensaje=f"Fallo en actualización: {str(e)}", usuario_id=Usuario.query.filter_by(rol='administrador').first().id))
                db.session.commit()

def envio_notificaciones():
    with app.app_context():
        tarea = Tarea.query.filter_by(nombre='envio_notificaciones').first()
        if tarea:
            try:
                print("Enviando notificaciones pendientes...")
                tarea.estado = 'completada'
                tarea.ultima_ejecucion = datetime.utcnow()
                db.session.commit()
            except Exception as e:
                tarea.estado = 'fallida'
                db.session.add(Notificacion(mensaje=f"Fallo en envío: {str(e)}", usuario_id=Usuario.query.filter_by(rol='administrador').first().id))
                db.session.commit()

def procesamiento_tareas():
    with app.app_context():
        tarea = Tarea.query.filter_by(nombre='procesamiento_tareas').first()
        if tarea:
            try:
                print("Procesando tareas pendientes...")
                tarea.estado = 'completada'
                tarea.ultima_ejecucion = datetime.utcnow()
                db.session.commit()
            except Exception as e:
                tarea.estado = 'fallida'
                db.session.add(Notificacion(mensaje=f"Fallo en procesamiento: {str(e)}", usuario_id=Usuario.query.filter_by(rol='administrador').first().id))
                db.session.commit()

def generacion_reportes():
    with app.app_context():
        tarea = Tarea.query.filter_by(nombre='generacion_reportes').first()
        if tarea:
            try:
                print("Generando reportes del sistema...")
                tarea.estado = 'completada'
                tarea.ultima_ejecucion = datetime.utcnow()
                db.session.commit()
            except Exception as e:
                tarea.estado = 'fallida'
                db.session.add(Notificacion(mensaje=f"Fallo en reportes: {str(e)}", usuario_id=Usuario.query.filter_by(rol='administrador').first().id))
                db.session.commit()

@app.route('/reportes', methods=['GET', 'POST'])
@login_required
def listar_reportes():
    page = request.args.get('page', 1, type=int)
    per_page = 10
    fecha_inicio = request.form.get('fecha_inicio')
    fecha_fin = request.form.get('fecha_fin')
    query = ReporteRecurso.query
    
    if fecha_inicio and fecha_fin:
        try:
            fecha_inicio_dt = datetime.strptime(fecha_inicio, '%Y-%m-%d')
            fecha_fin_dt = datetime.strptime(fecha_fin, '%Y-%m-%d').replace(hour=23, minute=59, second=59)
            query = query.filter(ReporteRecurso.fecha.between(fecha_inicio_dt, fecha_fin_dt))
            flash(f'Mostrando reportes desde {fecha_inicio} hasta {fecha_fin}', 'info')
        except ValueError:
            flash('Formato de fecha inválido. Usa YYYY-MM-DD.', 'danger')
    
    reportes_paginados = query.order_by(ReporteRecurso.fecha.desc()).paginate(page=page, per_page=per_page, error_out=False)
    # Mensaje de depuración con valores de cpu
    cpus = [str(reporte.cpu) for reporte in reportes_paginados.items]
    flash(f'Lista de reportes cargada exitosamente. CPUs en página {page}: {cpus}', 'success')
    return render_template('lista-reportes.html', reportes=reportes_paginados)

from app.utils import obtener_recursos_sistema

@app.route('/generar_reporte', methods=['POST'])
@login_required
def generar_reporte():
    recursos =obtener_recursos_sistema()
    reporte = ReporteRecurso(
        cpu=recursos['cpu'],
        memoria_porcentaje=recursos['memoria_porcentaje'],
        almacenamiento_porcentaje=recursos['almacenamiento_porcentaje'],
        tiempo_respuesta=recursos['tiempo_respuesta'],
        usuario_id=current_user.id
    )
    db.session.add(reporte)
    db.session.commit()
    flash('Reporte generado exitosamente.', 'success')
    return redirect(url_for('listar_reportes'))

@app.route('/descargar_reportes')
@login_required
def descargar_reportes():
    reportes = ReporteRecurso.query.order_by(ReporteRecurso.fecha.desc()).all()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['ID', 'CPU (%)', 'Memoria (%)', 'Almacenamiento (%)', 'Tiempo Respuesta (s)', 'Fecha', 'Usuario ID'])
    for reporte in reportes:
        writer.writerow([
            reporte.id,
            reporte.cpu,
            reporte.memoria_porcentaje,
            reporte.almacenamiento_porcentaje,
            reporte.tiempo_respuesta,
            reporte.fecha,
            reporte.usuario_id
        ])
    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=reportes.csv'}
    )

@app.route('/descargar_reportes_pdf')
@login_required
def descargar_reportes_pdf():
    reportes = ReporteRecurso.query.order_by(ReporteRecurso.fecha.desc()).all()
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    data = [['ID', 'CPU (%)', 'Memoria (%)', 'Almacenamiento (%)', 'Tiempo Respuesta (s)', 'Fecha']]
    for reporte in reportes:
        data.append([
            reporte.id,
            reporte.cpu,
            reporte.memoria_porcentaje,
            reporte.almacenamiento_porcentaje,
            reporte.tiempo_respuesta,
            str(reporte.fecha)
        ])
    table = Table(data)
    doc.build([table])
    buffer.seek(0)
    return Response(
        buffer.getvalue(),
        mimetype='application/pdf',
        headers={'Content-Disposition': 'attachment; filename=reportes.pdf'}
    )

def sincronizacion_datos():
    with app.app_context():
        tarea = Tarea.query.filter_by(nombre='sincronizacion_datos').first()
        if tarea:
            try:
                print("Sincronizando datos del sistema...")
                tarea.estado = 'completada'
                tarea.ultima_ejecucion = datetime.utcnow()
                db.session.commit()
            except Exception as e:
                tarea.estado = 'fallida'
                db.session.add(Notificacion(mensaje=f"Fallo en sincronización: {str(e)}", usuario_id=Usuario.query.filter_by(rol='administrador').first().id))
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
            except Exception as e:
                tarea.estado = 'fallida'
                db.session.add(Notificacion(mensaje=f"Fallo en respaldo: {str(e)}", usuario_id=Usuario.query.filter_by(rol='administrador').first().id))
                db.session.commit()

def limpieza_logs():
    with app.app_context():
        tarea = Tarea.query.filter_by(nombre='limpieza_logs').first()
        if tarea:
            try:
                print("Limpiando logs...")
                tarea.estado = 'completada'
                tarea.ultima_ejecucion = datetime.utcnow()
                db.session.commit()
            except Exception as e:
                tarea.estado = 'fallida'
                db.session.add(Notificacion(mensaje=f"Fallo en limpieza: {str(e)}", usuario_id=Usuario.query.filter_by(rol='administrador').first().id))
                db.session.commit()

def actualizaciones_software():
    with app.app_context():
        tarea = Tarea.query.filter_by(nombre='actualizaciones_software').first()
        if tarea:
            try:
                print("Buscando actualizaciones de software...")
                tarea.estado = 'completada'
                tarea.ultima_ejecucion = datetime.utcnow()
                db.session.commit()
            except Exception as e:
                tarea.estado = 'fallida'
                db.session.add(Notificacion(mensaje=f"Fallo en actualizaciones: {str(e)}", usuario_id=Usuario.query.filter_by(rol='administrador').first().id))
                db.session.commit()

def inicializar_tareas():
    with app.app_context():
        admin = Usuario.query.filter_by(rol='administrador').first()
        if not admin:
            return
        tareas_predeterminadas = [
            ('monitoreo_sistema', 'Monitoreo del sistema', 'diario', '00:00'),
            ('actualizacion_datos', 'Actualización de datos', 'diario', '01:00'),
            ('envio_notificaciones', 'Envío de notificaciones', 'diario', '08:00'),
            ('procesamiento_tareas', 'Procesamiento de tareas', 'diario', '02:00'),
            ('generacion_reportes', 'Generación de reportes', 'mensual', '03:00'),
            ('sincronizacion_datos', 'Sincronización de datos', 'semanal', '04:00'),
            ('respaldo_db', 'Respaldo diario', 'diario', '05:00'),
            ('limpieza_logs', 'Limpieza semanal', 'semanal', '06:00'),
            ('actualizaciones_software', 'Actualizaciones de software', 'mensual', '07:00'),
        ]
        for nombre, descripcion, frecuencia, hora in tareas_predeterminadas:
            if not Tarea.query.filter_by(nombre=nombre).first():
                tarea = Tarea(nombre=nombre, descripcion=descripcion, frecuencia=frecuencia, hora_ejecucion=hora, usuario_id=admin.id)
                db.session.add(tarea)
        db.session.commit()

        tareas = Tarea.query.all()
        for tarea in tareas:
            hora, minuto = map(int, tarea.hora_ejecucion.split(':'))
            if tarea.nombre == 'monitoreo_sistema':
                app.scheduler.add_job(monitoreo_sistema, 'cron', hour=hora, minute=minuto, id=tarea.nombre)
            elif tarea.nombre == 'actualizacion_datos':
                app.scheduler.add_job(actualizacion_datos, 'cron', hour=hora, minute=minuto, id=tarea.nombre)
            elif tarea.nombre == 'envio_notificaciones':
                app.scheduler.add_job(envio_notificaciones, 'cron', hour=hora, minute=minuto, id=tarea.nombre)
            elif tarea.nombre == 'procesamiento_tareas':
                app.scheduler.add_job(procesamiento_tareas, 'cron', hour=hora, minute=minuto, id=tarea.nombre)
            elif tarea.nombre == 'generacion_reportes':
                app.scheduler.add_job(generacion_reportes, 'cron', hour=hora, minute=minuto, day=1, id=tarea.nombre)
            elif tarea.nombre == 'sincronizacion_datos':
                app.scheduler.add_job(sincronizacion_datos, 'cron', hour=hora, minute=minuto, day_of_week='mon', id=tarea.nombre)
            elif tarea.nombre == 'respaldo_db':
                app.scheduler.add_job(respaldo_base_datos, 'cron', hour=hora, minute=minuto, id=tarea.nombre)
            elif tarea.nombre == 'limpieza_logs':
                app.scheduler.add_job(limpieza_logs, 'cron', hour=hora, minute=minuto, day_of_week='sun', id=tarea.nombre)
            elif tarea.nombre == 'actualizaciones_software':
                app.scheduler.add_job(actualizaciones_software, 'cron', hour=hora, minute=minuto, day=1, id=tarea.nombre)

@app.route('/')
def index():
    if current_user.is_authenticated:
        recursos = obtener_recursos_sistema()
        return render_template('index.html', 
                               cpu_usage=recursos['cpu'], 
                               memory_usage=recursos['memoria_porcentaje'], 
                               storage_usage=recursos['almacenamiento_porcentaje'])
    return render_template('index.html')

@app.route('/iniciar_sesion', methods=['GET', 'POST'])
def iniciar_sesion():
    form = FormularioLogin()
    if form.validate_on_submit():
        usuario = Usuario.query.filter_by(nombre_usuario=form.nombre_usuario.data).first()
        if usuario and usuario.verificar_contraseña(form.contraseña.data):
            login_user(usuario)
            flash('Inicio de sesión exitoso!', 'success')
            return redirect(url_for('panel_de_control')) 
        flash('Credenciales inválidas', 'danger')
    return render_template('iniciar_sesion.html', form=form)

@app.route('/registrar', methods=['GET', 'POST'])
def registrar():
    form = FormularioRegistro()
    if form.validate_on_submit():
        usuario = Usuario.query.filter_by(nombre_usuario=form.nombre_usuario.data).first()
        if usuario:
            flash('El nombre de usuario ya existe.', 'danger')
            return render_template('registrar.html', form=form)
        nuevo_usuario = Usuario(nombre_usuario=form.nombre_usuario.data, correo=form.correo.data)
        nuevo_usuario.establecer_contraseña(form.contraseña.data)
        db.session.add(nuevo_usuario)
        db.session.commit()
        flash('Usuario registrado exitosamente!', 'success')
        return redirect(url_for('iniciar_sesion'))
    return render_template('registrar.html', form=form)

@app.route('/cerrar_sesion')
@login_required
def cerrar_sesion():
    logout_user()
    return redirect(url_for('index'))

@app.route('/panel_de_control')  
@login_required
def panel_de_control():  
    recursos = obtener_recursos_sistema()
    tareas = Tarea.query.filter_by(usuario_id=current_user.id).all()
    notificaciones = Notificacion.query.filter_by(usuario_id=current_user.id, leida=False).all()
    return render_template('panel_de_control.html', 
                           recursos=recursos,
                           tareas=tareas,
                           notificaciones=notificaciones)

from sqlalchemy import case

@app.route('/tareas', methods=['GET'])
@login_required
def listar_tareas():
    page = request.args.get('page', 1, type=int)
    per_page = 5
    orden_frecuencia = case(
        {'unica': 0, 'diario': 1, 'semanal': 2, 'mensual': 3},
        value=Tarea.frecuencia
    )
    tareas_paginadas = Tarea.query.filter_by(usuario_id=current_user.id).order_by(
        orden_frecuencia.asc(),
        Tarea.hora_ejecucion.asc()
    ).paginate(page=page, per_page=per_page, error_out=False)
    # Mensaje de depuración con información sobre las tareas
    tareas_nombres = [tarea.nombre for tarea in tareas_paginadas.items]
    flash(f'Lista de tareas cargada exitosamente. Tareas en página {page}: {tareas_nombres}', 'success')
    return render_template('lista-tarea.html', tareas=tareas_paginadas)

@app.route('/crear_tarea', methods=['GET', 'POST'])
@login_required
def crear_tarea():
    form = FormularioTarea()
    if form.validate_on_submit():
        # Buscar la descripción correspondiente al nombre seleccionado
        descripcion = dict(form.nombre.choices)[form.nombre.data]
        tarea = Tarea(
            nombre=form.nombre.data,
            descripcion=descripcion,  # Usamos la descripción predefinida
            frecuencia=form.frecuencia.data,
            hora_ejecucion=form.hora_ejecucion.data,
            usuario_id=current_user.id,
            estado='pendiente'
        )
        db.session.add(tarea)
        db.session.commit()
        flash('Tarea creada exitosamente.', 'success')
        return redirect(url_for('listar_tareas'))
    return render_template('crear-tarea.html', form=form)

@app.route('/editar_tarea/<int:id>', methods=['GET', 'POST'])
@login_required
def editar_tarea(id):
    tarea = Tarea.query.get_or_404(id)
    if tarea.usuario_id != current_user.id and current_user.rol != 'administrador':
        flash('No tienes permiso para editar esta tarea.', 'danger')
        return redirect(url_for('listar_tareas'))
    form = FormularioTarea(obj=tarea)
    if form.validate_on_submit():
        tarea.nombre = form.nombre.data
        tarea.descripcion = dict(form.nombre.choices)[form.nombre.data]  # Actualizamos descripción
        tarea.frecuencia = form.frecuencia.data
        tarea.hora_ejecucion = form.hora_ejecucion.data
        db.session.commit()
        flash('Tarea actualizada exitosamente.', 'success')
        return redirect(url_for('listar_tareas'))
    return render_template('editar-tarea.html', form=form, tarea=tarea)

@app.route('/eliminar_tarea/<int:id>', methods=['POST'])
@login_required
def eliminar_tarea(id):
    tarea = Tarea.query.get_or_404(id)
    if tarea.usuario_id != current_user.id and current_user.rol != 'administrador':
        flash('No tienes permiso para eliminar esta tarea.', 'danger')
        return redirect(url_for('listar_tareas'))
    db.session.delete(tarea)
    db.session.commit()
    flash('Tarea eliminada exitosamente.', 'success')
    return redirect(url_for('listar_tareas'))


def ejecutar_tarea(tarea_id):
    with app.app_context():
        tarea = Tarea.query.get(tarea_id)
        if not tarea:
            return
        if tarea.nombre == 'monitoreo_sistema':
            recursos = obtener_recursos_sistema()
            reporte = ReporteRecurso(
                cpu=recursos['cpu'],
                memoria_porcentaje=recursos['memoria_porcentaje'],
                almacenamiento_porcentaje=recursos['almacenamiento_porcentaje'],
                tiempo_respuesta=recursos['tiempo_respuesta'],
                usuario_id=tarea.usuario_id,
                fecha=datetime.now()
            )
            db.session.add(reporte)
        tarea.ultima_ejecucion = datetime.now()
        if tarea.frecuencia == 'unica':
            tarea.estado = 'completada'
        db.session.commit()

def inicializar_tareas():
    scheduler.remove_all_jobs()
    tareas = Tarea.query.filter_by(estado='pendiente').all()
    for tarea in tareas:
        hora, minuto = map(int, tarea.hora_ejecucion.split(':'))
        if tarea.frecuencia == 'unica':
            # Programar tarea única para ejecutarse una vez en la próxima oportunidad
            scheduler.add_job(
                id=f'tarea_{tarea.id}',
                func=ejecutar_tarea,
                args=[tarea.id],
                trigger='date',  # Ejecutar una sola vez
                run_date=datetime.now().replace(hour=hora, minute=minuto, second=0, microsecond=0) if datetime.now().hour <= hora else datetime.now().replace(hour=hora, minute=minuto, second=0, microsecond=0) + timedelta(days=1),
                replace_existing=True
            )
        elif tarea.frecuencia == 'diario':
            scheduler.add_job(
                id=f'tarea_{tarea.id}',
                func=ejecutar_tarea,
                args=[tarea.id],
                trigger='cron',
                hour=hora,
                minute=minuto,
                replace_existing=True
            )
        elif tarea.frecuencia == 'semanal':
            scheduler.add_job(
                id=f'tarea_{tarea.id}',
                func=ejecutar_tarea,
                args=[tarea.id],
                trigger='cron',
                day_of_week='mon',
                hour=hora,
                minute=minuto,
                replace_existing=True
            )
        elif tarea.frecuencia == 'mensual':
            scheduler.add_job(
                id=f'tarea_{tarea.id}',
                func=ejecutar_tarea,
                args=[tarea.id],
                trigger='cron',
                day=1,
                hour=hora,
                minute=minuto,
                replace_existing=True
            )

@app.route('/eliminar_usuario/<int:id>', methods=['POST'])
@login_required
def eliminar_usuario(id):
    if current_user.rol != 'administrador':
        flash('Acceso denegado: Solo los administradores pueden eliminar usuarios.', 'danger')
        return redirect(url_for('panel_de_control'))
    usuario = Usuario.query.get_or_404(id)
    # Evitar que un administrador se elimine a sí mismo
    if usuario.id == current_user.id:
        flash('No puedes eliminar tu propia cuenta.', 'danger')
        return redirect(url_for('listar_usuarios'))
    db.session.delete(usuario)
    db.session.commit()
    flash('Usuario eliminado exitosamente.', 'success')
    return redirect(url_for('listar_usuarios'))