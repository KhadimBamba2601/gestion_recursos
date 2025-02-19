from flask import Flask, Blueprint, render_template, redirect, url_for, request, flash, send_file, session, make_response  # Añadido session y make_response
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_mail import Message
from models import Usuario, Proceso, Tarea, Log  # Importa los modelos
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, EmailField, SubmitField, SelectField, TextAreaField, DateTimeLocalField
from wtforms.validators import DataRequired, Length, Email, EqualTo, Optional
from io import BytesIO
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch # Importa inch
from datetime import datetime
import psutil, logging, csv, os, json
from flask_sqlalchemy import SQLAlchemy
import datetime

app = Flask(__name__)
app.config.from_object(os.environ.get('CONFIG_CLASS') or 'config.Config')

db = SQLAlchemy(app)

class LoginForm(FlaskForm):
    usuario = StringField('Nombre de usuario', validators=[DataRequired()])
    contrasena = PasswordField('Contraseña', validators=[DataRequired()])
    submit = SubmitField('Iniciar sesión')

class RegistroForm(FlaskForm):
    usuario = StringField('Nombre de usuario', validators=[DataRequired(), Length(min=3)])
    email = EmailField('Correo electrónico', validators=[DataRequired(), Email()])
    contrasena = PasswordField('Contraseña', validators=[DataRequired(), Length(min=8)])
    confirma_contrasena = PasswordField('Confirmar contraseña', validators=[DataRequired(), EqualTo('password', message='Las contraseñas deben coincidir')])
    submit = SubmitField('Registrarse')

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
    usuario = StringField('Usuario', validators=[Optional()])  # Filtrar por nombre de usuario
    submit = SubmitField('Generar Reporte')

class LogForm(FlaskForm):
    nivel = SelectField('Nivel', choices=[('info', 'Info'), ('warning', 'Warning'), ('error', 'Error')], validators=[DataRequired()])
    mensaje = TextAreaField('Mensaje', validators=[DataRequired()])
    submit = SubmitField('Crear')

class CrearTareaForm(FlaskForm):
    nombre = StringField('Nombre', validators=[DataRequired(), Length(max=255)])
    descripcion = TextAreaField('Descripción', validators=[Optional()])
    frecuencia = StringField('Frecuencia', validators=[DataRequired(), Length(max=255)])
    fecha_ejecucion = DateTimeLocalField('Fecha de ejecución', format='%Y-%m-%d %H:%M', validators=[DataRequired()])
    submit = SubmitField('Crear')

class EditarTareaForm(FlaskForm):
    nombre = StringField('Nombre', validators=[DataRequired(), Length(max=255)])
    descripcion = TextAreaField('Descripción', validators=[Optional()])
    frecuencia = StringField('Frecuencia', validators=[DataRequired(), Length(max=255)])
    fecha_ejecucion = DateTimeLocalField('Fecha de ejecución', format='%Y-%m-%d %H:%M', validators=[DataRequired()])
    submit = SubmitField('Guardar cambios')

class ContactForm(FlaskForm):
    destinatario = EmailField('Destinatario', validators=[DataRequired(), Email()])
    asunto = StringField('Asunto', validators=[DataRequired()])
    mensaje = StringField('Mensaje', validators=[DataRequired()])
    submit = SubmitField('Enviar correo')

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        usuario = form.usuario.data
        contrasena = form.contrasena.data
        user = Usuario.query.filter_by(nombre=usuario).first()

        if user and user.check_password(contrasena):
            login_user(user)
            flash('Inicio de sesión exitoso!', 'success')
            next_page = request.args.get('next')  # Obtiene la página a la que intentaba acceder
            return redirect(next_page or url_for('index'))  # Redirige a la página o al dashboard

        flash('Credenciales inválidas', 'danger')
        
    return render_template('login.html', form=form) # Pasa el formulario a la plantilla

@auth_bp.route('/registro', methods=['GET', 'POST'])
def registro():
    form = RegistroForm()
    if form.validate_on_submit():
        usuario = form.usuario.data  # Usa 'usuario' (o el nombre correcto)
        contrasena = form.contrasena.data
        email = form.email.data

        existing_user = Usuario.query.filter_by(usuario=usuario).first()  # Usa 'usuario'
        if existing_user:
            flash('Nombre de usuario ya existe.', 'danger')
            return render_template('registro.html', form=form) # Pasa el formulario

        existing_email = Usuario.query.filter_by(email=email).first()
        if existing_email:
            flash('Email ya existe.', 'danger')
            return render_template('registro.html', form=form) # Pasa el formulario

        try:
            nuevo_usuario = Usuario(usuario=usuario, email=email, contrasena=contrasena)  # Usa 'usuario'
            db.session.add(nuevo_usuario)
            db.session.commit()
            flash('¡Usuario registrado exitosamente!', 'success')
            return redirect(url_for('login'))
        except Exception as e:  # Captura excepciones (podrías ser más específico)
            db.session.rollback()
            flash(f'Error al registrar usuario: {e}', 'danger')
            print(f"Error al registrar usuario: {e}")
            return render_template('registro.html', form=form) # Pasa el formulario en caso de error

    return render_template('registro.html', form=form)  # Pasa el formulario a la plantilla

@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


usuario_bp = Blueprint('usuario', __name__)

class CrearUsuarioForm(FlaskForm):
    nombre = StringField('Nombre', validators=[DataRequired(), Length(min=3)])
    email = EmailField('Email', validators=[DataRequired(), Email()])
    contrasena = PasswordField('Contraseña', validators=[DataRequired(), Length(min=8)])
    rol = SelectField('Rol', choices=[('usuario', 'Usuario'), ('administrador', 'Administrador')], validators=[DataRequired()])
    submit = SubmitField('Crear')

class EditarUsuarioForm(FlaskForm):
    nombre = StringField('Nombre', validators=[DataRequired(), Length(min=3)])
    email = EmailField('Email', validators=[DataRequired(), Email()])
    contrasena = PasswordField('Contraseña (dejar en blanco para no cambiar)', validators=[Optional(), Length(min=8)]) # Contraseña opcional
    rol = SelectField('Rol', choices=[('usuario', 'Usuario'), ('administrador', 'Administrador')], validators=[DataRequired()])
    submit = SubmitField('Guardar')


@usuario_bp.route('/usuarios')
@login_required
def listar_usuarios():
    usuarios = Usuario.query.all()
    return render_template('lista-usuario.html', usuarios=usuarios)

@usuario_bp.route('/usuarios/crear', methods=['GET', 'POST'])
@login_required
def crear_usuario():
    form = CrearUsuarioForm()
    if form.validate_on_submit():
        nombre = form.nombre.data
        email = form.email.data
        contrasena = form.contrasena.data
        rol = form.rol.data

        nuevo_usuario = Usuario(nombre=nombre, email=email, contrasena=contrasena, rol=rol)
        db.session.add(nuevo_usuario)
        db.session.commit()
        flash('Usuario creado exitosamente', 'success')
        return redirect(url_for('usuario.listar_usuarios'))

    return render_template('crear-usuario.html', form=form)

@usuario_bp.route('/usuarios/editar/<int:id>', methods=['GET', 'POST'])
@login_required
def editar_usuario(id):
    usuario = Usuario.query.get_or_404(id)
    form = EditarUsuarioForm(obj=usuario) # Pre-carga los datos del usuario en el formulario

    if form.validate_on_submit():
        usuario.nombre = form.nombre.data
        usuario.contrasena= form.contrasena.data
        usuario.email = form.email.data
        usuario.rol = form.rol.data


        db.session.commit()
        flash('Usuario actualizado exitosamente', 'success')
        return redirect(url_for('usuario.listar_usuarios'))

    return render_template('editar-usuario.html', usuario=usuario, form=form)

@usuario_bp.route('/usuarios/eliminar/<int:id>', methods=['POST'])
@login_required
def eliminar_usuario(id):
    usuario = Usuario.query.get_or_404(id)
    db.session.delete(usuario)
    db.session.commit()
    flash('Usuario eliminado exitosamente', 'success')
    return redirect(url_for('usuario.listar_usuarios'))

@app.route('/dashboard')
@login_required
def dashboard():
    try:
        cpu_usage = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        memory_usage = memory.percent

        disk = psutil.disk_usage('/')
        storage_usage = disk.percent

        # Convertir los datos a formato JSON
        cpu_data = json.dumps([float(cpu_usage), 100 - float(cpu_usage)])
        memory_data = json.dumps([float(memory_usage), 100 - float(memory_usage)])
        storage_data = json.dumps([float(storage_usage), 100 - float(storage_usage)])


        # Obtener las tareas del usuario actual
        tasks = Tarea.query.filter_by(usuario_id=current_user.id).all()

        print(f"CPU Data: {cpu_data}")  
        print(f"Memory Data: {memory_data}")  
        print(f"Storage Data: {storage_data}")  
        return render_template('dashboard.html', 
                               tasks=tasks,  
                               cpu_usage=cpu_usage, 
                               memory_usage=memory_usage, 
                               storage_usage=storage_usage,
                               cpu_data=cpu_data, 
                               memory_data=memory_data,
                               storage_data=storage_data)

    except Exception as e:
        flash(f"Error al obtener información del sistema: {e}", "danger")
        print(f"Error en el dashboard: {e}")
        return render_template('dashboard.html', tasks=[])  # Pasar una lista vacía en caso de error

proceso_bp = Blueprint('proceso', __name__)

@proceso_bp.route('/', methods=['GET', 'POST'])  # Ruta para listar y crear
@login_required
def listar_procesos():
    form = ProcesoForm()
    if form.validate_on_submit():
        proceso = Proceso(
            nombre=form.nombre.data,
            descripcion=form.descripcion.data,
            estado=form.estado.data
        )
        db.session.add(proceso)
        db.session.commit()
        flash(f'Proceso {proceso.nombre} creado.', 'success')
        return redirect(url_for('proceso.listar_procesos'))  # Redirige a la lista
    procesos = Proceso.query.all()
    return render_template('lista-procesos.html', procesos=procesos, form=form)


@proceso_bp.route('/<int:proceso_id>', methods=['GET', 'POST'])  # Ruta para detalles y edición
@login_required
def detalles_proceso(proceso_id):
    proceso = Proceso.query.get_or_404(proceso_id)
    form = ProcesoForm(obj=proceso)  # Pre-carga los datos del proceso en el formulario
    if form.validate_on_submit():
        proceso.nombre = form.nombre.data
        proceso.descripcion = form.descripcion.data
        proceso.estado = form.estado.data
        db.session.commit()
        flash(f'Proceso {proceso.nombre} modificado.', 'success')
        return redirect(url_for('proceso.detalles_proceso', proceso_id=proceso_id))

    proceso_sistema = None
    try:
        for proc in psutil.process_iter(['name', 'pid']):
            if proc.info()['name'] == proceso.nombre:
                proceso_sistema = proc
                break
    except psutil.NoSuchProcess:
        flash(f'No se encontró el proceso {proceso.nombre} en el sistema.', 'warning')
    except Exception as e:
        flash(f'Error al obtener información del proceso: {e}', 'danger')

    return render_template('detalle-procesos.html', proceso=proceso, proceso_sistema=proceso_sistema, form=form)


@proceso_bp.route('/iniciar/<int:proceso_id>', methods=['POST'])
@login_required
def iniciar_proceso(proceso_id):
    proceso = Proceso.query.get_or_404(proceso_id)
    if proceso.estado == 'activo':
        flash(f'El proceso {proceso.nombre} ya está activo.', 'info')
        return redirect(url_for('proceso.detalles_proceso', proceso_id=proceso_id))

    try:
        proceso.estado = 'activo'
        db.session.commit()
        flash(f'Proceso {proceso.nombre} iniciado.', 'success')
    except Exception as e:
        flash(f'Error al iniciar el proceso: {e}', 'danger')
        db.session.rollback()  # Importante: Rollback en caso de error

    return redirect(url_for('proceso.detalles_proceso', proceso_id=proceso_id))


@proceso_bp.route('/detener/<int:proceso_id>', methods=['POST'])
@login_required
def detener_proceso(proceso_id):
    proceso = Proceso.query.get_or_404(proceso_id)
    if proceso.estado == 'inactivo':
        flash(f'El proceso {proceso.nombre} ya está inactivo.', 'info')
        return redirect(url_for('proceso.detalles_proceso', proceso_id=proceso_id))

    try:
        proceso.estado = 'inactivo'
        db.session.commit()
        flash(f'Proceso {proceso.nombre} detenido.', 'success')
    except Exception as e:
        flash(f'Error al detener el proceso: {e}', 'danger')
        db.session.rollback()  # Rollback en caso de error

    return redirect(url_for('proceso.detalles_proceso', proceso_id=proceso_id))


@proceso_bp.route('/monitor')
@login_required
def monitor_procesos():
    procesos_sistema = []
    try:
        for proc in psutil.process_iter(['name', 'status', 'cpu_percent', 'memory_percent', 'pid']):
            procesos_sistema.append({
                'nombre': proc.info()['name'],
                'estado': proc.info()['status'],
                'cpu_uso': proc.info()['cpu_percent'],
                'memoria_uso': proc.info()['memory_percent'],
                'pid': proc.info()['pid']
            })
    except Exception as e:
        flash('Error al obtener la lista de procesos del sistema: {e}', 'danger')

    return render_template('detalle-procesos.html', procesos_sistema=procesos_sistema)

reporte_bp = Blueprint('reporte', __name__)

@reporte_bp.route('/reportes', methods=['GET', 'POST'])
@login_required
def dashboard():
    usuarios_form = ReporteUsuariosForm()
    tareas_form = ReporteTareasForm()

    usuarios_count = Usuario.query.count()
    procesos_count = Proceso.query.count()
    tareas_count = Tarea.query.count()

    return render_template('dashboard-reportes.html',
                           usuarios_count=usuarios_count,
                           procesos_count=procesos_count,
                           tareas_count=tareas_count,
                           usuarios_form=usuarios_form,
                           tareas_form=tareas_form)

@reporte_bp.route('/reportes/usuarios/pdf', methods=['POST'])
@login_required
def reporte_usuarios_pdf():
    usuarios_form = ReporteUsuariosForm(request.form)

    if usuarios_form.validate_on_submit():
        nombre_filtro = usuarios_form.nombre.data
        rol_filtro = usuarios_form.rol.data

        usuarios = Usuario.query.filter(
            Usuario.nombre.like(f"%{nombre_filtro}%") if nombre_filtro else True,
            Usuario.rol == rol_filtro if rol_filtro else True
        ).all()


        output = BytesIO()
        p = canvas.Canvas(output, pagesize=letter)

        p.drawString(100, 750, "Reporte de Usuarios")
        p.drawString(100, 730, f"Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

        y_position = 700
        for usuario in usuarios:
            p.drawString(100, y_position, f"Nombre: {usuario.nombre}")
            p.drawString(200, y_position, f"Email: {usuario.email}")
            p.drawString(350, y_position, f"Rol: {usuario.rol}")
            y_position -= 20

        p.showPage()
        p.save()
        output.seek(0)

        return send_file(output,
                         mimetype='application/pdf',
                         attachment_filename='reporte_usuarios.pdf',
                         as_attachment=True)
    else:
        flash("Error en el formulario", "danger")
        return redirect(url_for('reporte.dashboard'))

@reporte_bp.route('/reportes/tareas/csv', methods=['POST'])
@login_required
def reporte_tareas_csv():
    tareas_form = ReporteTareasForm(request.form)

    if tareas_form.validate_on_submit():
        nombre_filtro = tareas_form.nombre.data
        usuario_filtro = tareas_form.usuario.data

        tareas = Tarea.query.filter(
            Tarea.nombre.like(f"%{nombre_filtro}%") if nombre_filtro else True,
            Tarea.usuario.nombre.like(f"%{usuario_filtro}%") if usuario_filtro else True
        ).all()

        output = BytesIO()
        writer = csv.writer(output)

        writer.writerow(['Nombre', 'Descripción', 'Frecuencia', 'Fecha de Ejecución', 'Usuario'])

        for tarea in tareas:
            writer.writerow([tarea.nombre, tarea.descripcion, tarea.frecuencia, tarea.fecha_ejecucion, tarea.usuario.nombre])

        output.seek(0)

        return send_file(output,
                         mimetype='text/csv',
                         attachment_filename='reporte_tareas.csv',
                         as_attachment=True)
    else:
        flash("Error en el formulario", "danger")
        return redirect(url_for('reporte.dashboard'))
    
log_bp = Blueprint('log', __name__)

@log_bp.route('/logs')
@login_required
def listar_logs():
    try:
        with open('mi_aplicacion.log', 'r') as f:
            logs = f.readlines()
        return render_template('lista-log.html', logs=logs)
    except FileNotFoundError:
        flash('Archivo de logs no encontrado.', 'warning')
        return render_template('lista-log.html', logs=[])
    except Exception as e:
        flash(f'Error al leer el archivo de logs: {e}', 'danger')
        logging.exception('Error al leer el archivo de logs:')
        return render_template('lista-log.html', logs=[])
    
@log_bp.route('/logs/crear', methods=['GET', 'POST'])
@login_required
def crear_log():
    form = LogForm()
    if form.validate_on_submit():
        nivel = form.nivel.data
        mensaje = form.mensaje.data

        nuevo_log = Log(nivel=nivel, mensaje=mensaje)
        try:
            db.session.add(nuevo_log)
            db.session.commit()
            flash('Log creado con éxito.', 'success')
            return redirect(url_for('log.listar_logs'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error al crear el log: {e}', 'danger')
            logging.exception('Error al crear el log:')
            return render_template('crear-log.html', form=form)  # Re-render form with errors

    return render_template('crear-log.html', form=form)

@log_bp.route('/logs/eliminar/<int:log_id>', methods=['POST'])
@login_required
def eliminar_log(log_id):
    log_a_eliminar = Log.query.get_or_404(log_id)
    try:
        db.session.delete(log_a_eliminar)
        db.session.commit()
        flash('Log eliminado con éxito.', 'success')
    except Exception as e:
        flash(f'Error al eliminar el log: {e}', 'danger')
        db.session.rollback()
    return redirect(url_for('log.listar_logs'))

tarea_bp = Blueprint('tarea', __name__)

@tarea_bp.route('/tarea')
@login_required
def listar_tareas():
    tareas = Tarea.query.filter_by(usuario_id=current_user.id).all()
    return render_template('lista-tarea.html', tareas=tareas)

@tarea_bp.route('/tareas/crear', methods=['GET', 'POST'])
@login_required
def crear_tarea():
    form = CrearTareaForm()
    if form.validate_on_submit():
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
        return redirect(url_for('tarea.listar_tareas'))
    return render_template('crear-tarea.html', form=form)

@tarea_bp.route('/tareas/editar/<int:tarea_id>', methods=['GET', 'POST'])
@login_required
def editar_tarea(tarea_id):
    tarea = Tarea.query.get_or_404(tarea_id)

    if tarea.usuario_id != current_user.id:
        flash('No tienes permiso para editar esta tarea.', 'danger')
        return redirect(url_for('tarea.listar_tareas'))

    form = EditarTareaForm(obj=tarea) # Pre-carga los datos de la tarea en el formulario
    if form.validate_on_submit():
        tarea.nombre = form.nombre.data
        tarea.descripcion = form.descripcion.data
        tarea.frecuencia = form.frecuencia.data
        tarea.fecha_ejecucion = form.fecha_ejecucion.data
        db.session.commit()
        flash('Tarea actualizada con éxito.', 'success')
        return redirect(url_for('tarea.listar_tareas'))
    return render_template('editar-tarea.html', tarea=tarea, form=form)

@tarea_bp.route('/tareas/eliminar/<int:tarea_id>', methods=['POST'])
@login_required
def eliminar_tarea(tarea_id):
    tarea = Tarea.query.get_or_404(tarea_id)

    if tarea.usuario_id != current_user.id:
        flash('No tienes permiso para eliminar esta tarea.', 'danger')
        return redirect(url_for('tarea.listar_tareas'))

    db.session.delete(tarea)
    db.session.commit()
    flash('Tarea eliminada con éxito.', 'success')
    return redirect(url_for('tarea.listar_tareas'))

email_bp = Blueprint('email', __name__)

from flask_mail import Message,Mail
mail = Mail(app)

@email_bp.route('/enviar_logs', methods=['GET', 'POST'])
@login_required
def enviar_logs():
    form = ContactForm()  # Reutiliza el formulario de contacto o crea uno específico
    if form.validate_on_submit():
        destinatario = form.destinatario.data
        asunto = "Registros de la aplicación"
        try:
            with open('mi_aplicacion.log', 'r') as f:
                contenido_log = f.read()
            msg = Message(asunto, recipients=[destinatario], body=contenido_log)
            mail.send(msg)
            flash('Registros enviados por correo electrónico con éxito.', 'success')
            return redirect(url_for('email.enviar_logs'))
        except FileNotFoundError:
            flash('Archivo de logs no encontrado.', 'warning')
        except Exception as e:
            flash(f'Error al enviar los registros por correo electrónico: {e}', 'danger')
            logging.exception('Error al enviar los registros por correo electrónico:')
    return render_template('email/enviar-correo.html', form=form)

reporte_bp = Blueprint('reporte', __name__)  # Nombre del blueprint: 'reporte'

@reporte_bp.route('/generar_reporte', methods=['GET', 'POST'])
@login_required
def generar_reporte():
    if request.method == 'POST':
        tipo_reporte = request.form.get('tipo_reporte')
        formato_reporte = request.form.get('formato_reporte')
        fecha_inicio_str = request.form.get('fecha_inicio')
        fecha_fin_str = request.form.get('fecha_fin')

        try:
            fecha_inicio = datetime.datetime.strptime(fecha_inicio_str, '%Y-%m-%d').date()
            fecha_fin = datetime.datetime.strptime(fecha_fin_str, '%Y-%m-%d').date()

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
                return redirect(url_for('reporte.generar_reporte'))  # Correcto

            if formato_reporte == 'pdf' or formato_reporte == 'csv':
                # Guarda datos en la sesión
                session['datos_reporte'] = datos_reporte
                session['titulo_reporte'] = titulo_reporte
                session['formato_reporte'] = formato_reporte
                session['tipo_reporte'] = tipo_reporte
                session['fecha_inicio'] = fecha_inicio_str
                session['fecha_fin'] = fecha_fin_str
                return redirect(url_for('reporte.detalle_reporte'))  # Correcto
            else:
                flash("Formato de reporte no válido.", "danger")
                return redirect(url_for('reporte.generar_reporte'))  # Correcto

        except ValueError:
            flash("Formato de fecha incorrecto. Debe ser YYYY-MM-DD.", "danger")
            return redirect(url_for('reporte.generar_reporte'))  # Correcto
        except Exception as e:
            flash(f"Error al generar el reporte: {e}", "danger")
            logging.exception("Error al generar el reporte:")
            return redirect(url_for('reporte.generar_reporte'))  # Correcto

    return render_template('generar_reporte.html')  # Formulario

def generar_pdf(titulo, datos):
    buffer = BytesIO()
    p = canvas.Canvas(buffer, pagesize=letter)
    p.setFont("Helvetica-Bold", 16)
    p.drawString(inch, 10.5 * inch, titulo)

    p.setFont("Helvetica", 12)
    y_pos = 9.5 * inch

    encabezados = list(datos[0].keys()) if datos else []
    for encabezado in encabezados:
        p.drawString(inch, y_pos, str(encabezado))
        inch += 1  # Incremento fijo (puedes ajustarlo)

    inch = 1
    y_pos -= 0.5 * inch

    for dato in datos:
        for valor in dato.values():
            p.drawString(inch, y_pos, str(valor))
            inch += 1  # Incremento fijo (puedes ajustarlo)
        inch = 1
        y_pos -= 0.5 * inch

    p.save()
    buffer.seek(0)

    response = make_response(buffer.getvalue())
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f'attachment; filename="{titulo}.pdf"'
    return response

def generar_csv(titulo, datos):
    output = BytesIO()
    writer = csv.writer(output)

    if datos:
        writer.writerow(datos[0].keys())
        for row in datos:
            writer.writerow(row.values())

    output.seek(0)
    response = make_response(output.getvalue())
    response.headers['Content-Type'] = 'text/csv'
    response.headers['Content-Disposition'] = f'attachment; filename="{titulo}.csv"'
    return response

@reporte_bp.route('/detalle_reporte')
@login_required
def detalle_reporte():
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
        return generar_pdf(titulo_reporte, datos_reporte)
    elif formato_reporte == 'csv':
        return generar_csv(titulo_reporte, datos_reporte)

    return render_template('detalle-reporte.html', datos_reporte=datos_reporte, titulo_reporte=titulo_reporte, tipo_reporte=tipo_reporte, fecha_inicio=fecha_inicio, fecha_fin=fecha_fin)

# --- Funciones para obtener datos (IMPLEMENTACIÓN - ADAPTAR A TUS MODELOS) ---

def obtener_datos_rendimiento(fecha_inicio, fecha_fin):
    try:
        logs = Log.query.filter(Log.fecha >= fecha_inicio, Log.fecha <= fecha_fin).all()
        datos_rendimiento = []
        for log in logs:
            cpu_uso = log.mensaje.get('cpu_uso')
            memoria_uso = log.mensaje.get('memoria_uso')
            if cpu_uso and memoria_uso:
                datos_rendimiento.append({
                    'fecha': log.fecha,
                    'cpu_promedio': cpu_uso,
                    'memoria_promedio': memoria_uso
                })
        return datos_rendimiento
    except Exception as e:
        logging.error(f"Error al obtener datos de rendimiento: {e}")
        return []

def obtener_datos_tiempos_respuesta(fecha_inicio, fecha_fin):
    try:
        tareas = Tarea.query.filter(Tarea.fecha_inicio >= fecha_inicio, Tarea.fecha_fin <= fecha_fin).all()
        datos_tiempos_respuesta = []
        for tarea in tareas:
            if tarea.fecha_inicio and tarea.fecha_fin:
                tiempo_respuesta = (tarea.fecha_fin - tarea.fecha_inicio).total_seconds()
                datos_tiempos_respuesta.append({
                    'fecha': tarea.fecha_inicio,
                    'tarea': tarea.name,
                    'tiempo_respuesta': tiempo_respuesta
                })
        return datos_tiempos_respuesta
    except Exception as e:
        logging.error(f"Error al obtener datos de tiempos de respuesta: {e}")
        return []

def obtener_datos_utilizacion_recursos(fecha_inicio, fecha_fin):
    try:
        logs = Log.query.filter(Log.fecha >= fecha_inicio, Log.fecha <= fecha_fin).all()
        datos_utilizacion = []
        for log in logs:
            disco_uso = log.mensaje.get('disco_uso')
            if disco_uso:
                datos_utilizacion.append({
                    'fecha': log.fecha,
                    'disco_promedio': disco_uso,
                })
        return datos_utilizacion
    except Exception as e:  # Captura la excepción y la guarda en la variable 'e'
        logging.error(f"Error al obtener datos de utilización de recursos: {e}") # Registra el error con logging
        return []  # Retorna una lista vacía en caso de error