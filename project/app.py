from flask import Flask, render_template, redirect, url_for, request, session, flash, send_from_directory, make_response
from models import db
from config import Config
from views import auth_bp, usuario_bp, tarea_bp, proceso_bp, reporte_bp, log_bp, email_bp  # Asegúrate de tener reporte_bp
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_migrate import Migrate
from models import Usuario, Tarea, Proceso, Log
import logging, os, psutil
import datetime
from io import BytesIO
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
import csv

app = Flask(__name__)
app.config.from_object(Config) # Usa la configuración de Flask


db.init_app(app)
migrate = Migrate(app, db)  # Inicializa Migrate

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'auth.login'

from models import Usuario, Tarea, Proceso, Log

@login_manager.user_loader
def load_user(user_id):
    return Usuario.query.get(int(user_id))

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        usuario = request.form.get('username')  # Corregido: usuario y usa .get()
        password = request.form.get('password')  # Usa .get() para evitar KeyError

        if not usuario or not password:  # Corregido: usuario
            flash('Por favor, introduce usuario y contraseña.', 'warning')
            return render_template('login.html')

        user = Usuario.query.filter_by(usuario=usuario).first()  # Corregido: usuario

        if user and user.check_password(password):
            login_user(user)
            flash('Inicio de sesión exitoso!', 'success')

            next_page = request.args.get('next')
            return redirect(next_page or url_for('dashboard'))

        flash('Credenciales inválidas', 'danger')

    return render_template('login.html')
@app.route('/registro', methods=['GET', 'POST'])
def registro():
    if request.method == 'POST':
        usuario = request.form['username']  
        email = request.form['email']
        contrasena = request.form['password']
        confirma_contrasena = request.form['confirm_password']  

        if contrasena != confirma_contrasena:
            flash('Las contraseñas no coinciden.', 'danger')
            return redirect(url_for('registro'))

        if len(contrasena) < 8:
            flash('La contraseña debe tener al menos 8 caracteres.', 'danger')
            return redirect(url_for('registro'))

        try:
            if Usuario.query.filter_by(usuario=usuario).first():  # Usa 'usuario' (o el campo correcto)
                flash('Nombre de usuario ya existe.', 'danger')
                return redirect(url_for('registro'))

            if Usuario.query.filter_by(email=email).first():
                flash('Email ya existe.', 'danger')
                return redirect(url_for('registro'))

            new_user = Usuario(usuario=usuario, email=email, contrasena=contrasena)  # Usa Usuario y el setter de contrasena

            db.session.add(new_user)
            db.session.commit()

            flash('Usuario registrado exitosamente.', 'success')
            return redirect(url_for('login'))

        except Exception as e:
            db.session.rollback()
            flash(f'Error al registrar usuario: {e}', 'danger')
            print(f"Error en la base de datos: {e}")  # Loggea el error
            return redirect(url_for('registro'))  # Redirige a registro en caso de error

    return render_template('registro.html')
from sqlalchemy.exc import OperationalError  # Importa la excepción específica

@app.route('/usuarios')
@login_required
def usuarios():
    if current_user.rol != 'administrador':
        flash('No tienes permiso para ver esta página.', 'danger')
        return redirect(url_for('dashboard'))

    try:
        usuarios = Usuario.query.all()  # Obtiene todos los usuarios
        return render_template('lista-usuario.html', usuarios=usuarios)  # Usa 'usuarios' (consistente)
    except OperationalError as e:  # Captura excepciones específicas
        db.session.rollback()  # Rollback en caso de error de BD
        flash(f'Error de conexión a la base de datos: {e}', 'danger')
        print(f"Error al obtener usuarios (OperationalError): {e}")
        usuarios = []  # Inicializa usuarios a una lista vacía
        return render_template('lista-usuario.html', usuarios=usuarios)  # Renderiza el mismo template con la lista vacía
    except Exception as e: # Captura otras excepciones
        db.session.rollback() # Rollback en caso de error
        flash(f'Ocurrió un error al obtener los usuarios: {e}', 'danger')
        print(f"Error al obtener usuarios: {e}")
        usuarios = []  # Inicializa usuarios a una lista vacía
        return render_template('lista-usuario.html', usuarios=usuarios)  # Renderiza el mismo template con la lista vacía
@app.route('/usuarios/editar/<int:usuario_id>', methods=['GET', 'POST'])
@login_required
def editar_usuario(usuario_id):
    usuario = Usuario.query.get_or_404(usuario_id)  # Usa Usuario

    if request.method == 'POST':
        usuario.usuario = request.form['username']  # Usa 'usuario' (o el campo correcto)
        usuario.email = request.form['email']
        usuario.rol = request.form.get('rol', 'usuario')

        if request.form['password']:
            usuario.contrasena = request.form['password']  # Usa el setter de contrasena

        try:
            db.session.commit()
            flash('Usuario actualizado con éxito!', 'success')
            return redirect(url_for('usuarios'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error al actualizar el usuario: {e}', 'danger')
            print(f"Error al actualizar usuario: {e}")

    return render_template('editar-usuario.html', usuario=usuario)

@app.route('/usuarios/eliminar/<int:usuario_id>', methods=['POST'])
@login_required
def eliminar_usuario(usuario_id):
    usuario = Usuario.query.get_or_404(usuario_id)  # Usa Usuario
    try:
        db.session.delete(usuario)
        db.session.commit()
        flash('Usuario eliminado con éxito!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error al eliminar el usuario: {e}', 'danger')
        print(f"Error al eliminar usuario: {e}")
    return redirect(url_for('usuarios'))

@app.route('/usuarios/crear', methods=['GET', 'POST'])
@login_required
def crear_usuario():
    if request.method == 'POST':
        usuario = request.form['username']  # Usa 'username' (o el campo correcto)
        email = request.form['email']
        contrasena = request.form['password']
        rol = request.form.get('rol', 'usuario')

        if len(contrasena) < 8:
            flash('La contraseña debe tener al menos 8 caracteres.', 'danger')
            return redirect(url_for('crear-usuario'))

        if Usuario.query.filter_by(usuario=usuario).first():  # Usa 'usuario'
            flash('Nombre de usuario ya existe.', 'danger')
            return redirect(url_for('crear-usuario'))

        if Usuario.query.filter_by(email=email).first():
            flash('Email ya existe.', 'danger')
            return redirect(url_for('crear-usuario'))

        try:
            new_user = Usuario(usuario=usuario, email=email, contrasena=contrasena, rol=rol) # Usa Usuario y el setter de contrasena
            db.session.add(new_user)
            db.session.commit()
            flash('Usuario creado con éxito!', 'success')
            return redirect(url_for('lista-usuario'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error al crear el usuario: {e}', 'danger')
            print(f"Error al crear usuario: {e}")
            return render_template('crear-usuario.html')  # Renderiza el template en caso de error

    return render_template('crear-usuario.html')

@app.route('/dashboard')  # O la ruta que corresponda a tu dashboard
@login_required
def dashboard():
    try:
        tasks = Tarea.query.filter_by(usuario_id=current_user.id).all()  # Obtén las tareas del usuario actual

        cpu_usage = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        memory_usage = memory.percent

        disk = psutil.disk_usage('/')
        storage_usage = disk.percent

        return render_template('dashboard.html', 
                               cpu_usage=cpu_usage, 
                               memory_usage=memory_usage, 
                               storage_usage=storage_usage, 
                               tasks=tasks,
                               form=LogForm()) # Pasa el formulario LogForm

    except Exception as e:  # Captura excepciones (podrías ser más específico)
        flash(f"Error al obtener información del sistema: {e}", "danger")  # Muestra un mensaje flash
        print(f"Error en el dashboard: {e}")  # Imprime el error en la consola
        return render_template('dashboard.html', tasks=[], form=LogForm()) # Retorna un template con tasks vacías para evitar errores. 
from sqlalchemy.exc import IntegrityError  # Importa IntegrityError

@app.route('/tarea', methods=['GET', 'POST'])
@login_required
def tasks():
    if request.method == 'POST':
        task_name = request.form['task_name']
        description = request.form['description']
        try:
            new_task = Tarea(name=task_name, description=description, usuario_id=current_user.id)  # Usa Tarea
            db.session.add(new_task)
            db.session.commit()
            flash('Tarea creada con éxito!', 'success')
            return redirect(url_for('dashboard'))
        except IntegrityError as e:  # Captura errores de unicidad
            db.session.rollback()
            flash(f'Error: Ya existe una tarea con ese nombre.', 'danger')  # Mensaje más específico
            print(f"Error al crear tarea (IntegrityError): {e}")
        except Exception as e: # Captura otras excepciones
            db.session.rollback()
            flash(f'Error al crear la tarea: {e}', 'danger')
            print(f"Error al crear tarea: {e}")
    return render_template('lista-tarea.html')  # Retorna el template siempre

from flask import Blueprint, render_template, redirect, url_for, request, flash
from models import Log
from forms import LogForm  # Si tienes un archivo forms.py para tus formularios

log_bp = Blueprint('log', __name__)

@log_bp.route('/logs')
@login_required
def listar_logs():
    try:
        logs = Log.query.order_by(Log.fecha.desc()).all()  # Ordena los logs por fecha (más recientes primero)
        return render_template('lista-log.html', logs=logs, form=LogForm())  # Pasa el formulario a la plantilla
    except Exception as e:
        flash(f'Ocurrió un error al obtener los logs: {e}', 'danger')
        logging.exception('Ocurrió un error al obtener los logs:')  # Usa logging.exception para registrar la traza completa
        return render_template('lista-log.html', logs=[], form=LogForm())  # Devuelve una lista vacía y el formulario en caso de error

@log_bp.route('/logs/crear', methods=['GET', 'POST'])
@login_required
def crear_log():
    form = LogForm()
    if form.validate_on_submit():
        nivel = form.nivel.data
        mensaje = form.mensaje.data

        nuevo_log = Log(nivel=nivel, mensaje=mensaje)  # Crea una instancia del modelo Log
        try:
            db.session.add(nuevo_log)  # Agrega el nuevo log a la sesión de la base de datos
            db.session.commit()  # Guarda los cambios en la base de datos
            flash('Log creado con éxito.', 'success')
            logging.info(f'Se creó un nuevo log: {mensaje}')  # Registra el evento en el archivo de log
            return redirect(url_for('log.listar_logs'))  # Redirige a la lista de logs
        except Exception as e:
            db.session.rollback()  # Revierte los cambios en caso de error
            flash(f'Error al crear el log: {e}', 'danger')
            logging.exception('Error al crear el log:')  # Registra la excepción completa
            return render_template('crear-log.html', form=form)  # Re-renderiza el formulario con los errores

    return render_template('crear-log.html', form=form)  # Renderiza el formulario vacío por primera vez

@log_bp.route('/logs/eliminar/<int:log_id>', methods=['POST'])
@login_required
def eliminar_log(log_id):
    log_a_eliminar = Log.query.get_or_404(log_id)  # Obtiene el log o devuelve 404 si no existe
    try:
        db.session.delete(log_a_eliminar)  # Elimina el log de la base de datos
        db.session.commit()  # Guarda los cambios en la base de datos
        flash('Log eliminado con éxito.', 'success')  # Muestra un mensaje flash de éxito
    except Exception as e:  # Captura cualquier excepción que pueda ocurrir
        db.session.rollback()  # Revierte la transacción en caso de error
        flash(f'Error al eliminar el log: {e}', 'danger')  # Muestra un mensaje flash de error
        logging.exception('Error al eliminar el log:')  # Registra el error en el archivo de logs
    return redirect(url_for('log.listar_logs'))  # Redirige a la página de lista de logs

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
                return redirect(url_for('reporte.generar_reporte'))  # Corregido: 'reporte.generar_reporte'

            if formato_reporte == 'pdf' or formato_reporte == 'csv':
                # Guarda datos en la sesión
                session['datos_reporte'] = datos_reporte
                session['titulo_reporte'] = titulo_reporte
                session['formato_reporte'] = formato_reporte
                session['tipo_reporte'] = tipo_reporte # Guarda el tipo de reporte
                session['fecha_inicio'] = fecha_inicio_str # Guarda la fecha inicio
                session['fecha_fin'] = fecha_fin_str # Guarda la fecha fin
                return redirect(url_for('reporte.detalle_reporte'))  # Corregido: 'reporte.detalle_reporte'
            else:
                flash("Formato de reporte no válido.", "danger")
                return redirect(url_for('reporte.generar_reporte'))  # Corregido: 'reporte.generar_reporte'

        except ValueError:
            flash("Formato de fecha incorrecto. Debe ser YYYY-MM-DD.", "danger")
            return redirect(url_for('reporte.generar_reporte'))  # Corregido: 'reporte.generar_reporte'
        except Exception as e:
            flash(f"Error al generar el reporte: {e}", "danger")
            logging.exception("Error al generar el reporte:")
            return redirect(url_for('reporte.generar_reporte'))  # Corregido: 'reporte.generar_reporte'

    return render_template('generar_reporte.html')  # Formulario para generar reportes

def generar_pdf(titulo, datos):
    buffer = BytesIO()
    p = canvas.Canvas(buffer, pagesize=letter)
    p.setFont("Helvetica-Bold", 16)
    p.drawString(inch, 10.5 * inch, titulo) # Ajusta la posición del título

    p.setFont("Helvetica", 12)
    y_pos = 9.5 * inch  # Posición inicial para los datos

    # Encabezados de la tabla (ajustar según tus datos)
    encabezados = list(datos[0].keys()) if datos else []  # Obtén las claves del diccionario como encabezados
    for encabezado in encabezados:
        p.drawString(inch, y_pos, str(encabezado)) # Ajusta la posición de los encabezados
        inch_increment = 1 # Incremento en pulgadas para la siguiente columna (ajusta según la longitud de los datos)
        inch += inch_increment

    inch = 1 # Restablece la posición en x a 1 pulgada para la siguiente fila
    y_pos -= 0.5 * inch # Desciende una línea para los datos

    for dato in datos:
        for valor in dato.values():
            p.drawString(inch, y_pos, str(valor))
            inch_increment = 1 # Incremento en pulgadas para la siguiente columna (ajusta según la longitud de los datos)
            inch += inch_increment
        inch = 1 # Restablece la posición en x a 1 pulgada para la siguiente fila
        y_pos -= 0.5 * inch # Desciende una línea para los datos

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
        writer.writerow(datos[0].keys())  # Escribe los encabezados
        for row in datos:
            writer.writerow(row.values())  # Escribe los datos

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

    return render_template('detalle-reporte.html', datos_reporte=datos_reporte, titulo_reporte=titulo_reporte, tipo_reporte=tipo_reporte, fecha_inicio=fecha_inicio, fecha_fin=fecha_fin) # Pasar datos al template

# --- Funciones para obtener datos (IMPLEMENTACIÓN) ---

def obtener_datos_rendimiento(fecha_inicio, fecha_fin):
    try:
        # Ejemplo usando Log (adaptar a tus modelos y datos de rendimiento)
        logs = Log.query.filter(Log.fecha >= fecha_inicio, Log.fecha <= fecha_fin).all()

        datos_rendimiento = []
        for log in logs:
            # Extrae o calcula los datos de rendimiento del log (CPU, memoria, etc.)
            # Esto dependerá de cómo estés registrando esos datos en tus logs
            # Aquí te doy un ejemplo, pero AJÚSTALO a tu lógica
            cpu_uso = log.mensaje.get('cpu_uso')  # Asumiendo que guardas el uso de CPU en el mensaje del log
            memoria_uso = log.mensaje.get('memoria_uso') # Asumiendo que guardas el uso de memoria en el mensaje del log
            if cpu_uso and memoria_uso:  # Verifica si existen los datos
                datos_rendimiento.append({
                    'fecha': log.fecha,
                    'cpu_promedio': cpu_uso,
                    'memoria_promedio': memoria_uso
                })
        return datos_rendimiento

    except Exception as e:
        logging.error(f"Error al obtener datos de rendimiento: {e}")
        return []  # Devuelve una lista vacía en caso de error

def obtener_datos_tiempos_respuesta(fecha_inicio, fecha_fin):
    try:
        # Ejemplo usando Tarea (adaptar a tus modelos y datos de tiempos de respuesta)
        tareas = Tarea.query.filter(Tarea.fecha_inicio >= fecha_inicio, Tarea.fecha_fin <= fecha_fin).all()

        datos_tiempos_respuesta = []
        for tarea in tareas:
            # Calcula el tiempo de respuesta de la tarea (si tienes las fechas de inicio y fin)
            if tarea.fecha_inicio and tarea.fecha_fin:
                tiempo_respuesta = (tarea.fecha_fin - tarea.fecha_inicio).total_seconds()
                datos_tiempos_respuesta.append({
                    'fecha': tarea.fecha_inicio,  # O la fecha que sea más relevante
                    'tarea': tarea.name, # Nombre de la tarea
                    'tiempo_respuesta': tiempo_respuesta
                })
        return datos_tiempos_respuesta

    except Exception as e:
        logging.error(f"Error al obtener datos de tiempos de respuesta: {e}")
        return []

def obtener_datos_utilizacion_recursos(fecha_inicio, fecha_fin):
    try:
        # Ejemplo usando Log (adaptar a tus modelos y datos de utilización de recursos)
        logs = Log.query.filter(Log.fecha >= fecha_inicio, Log.fecha <= fecha_fin).all()

        datos_utilizacion = []
        for log in logs:
            # Extrae o calcula los datos de utilización de recursos del log
            # Esto dependerá de cómo estés registrando esos datos
            # Aquí te doy un ejemplo, pero AJÚSTALO a tu lógica
            disco_uso = log.mensaje.get('disco_uso') # Asumiendo que guardas el uso de disco en el mensaje del log
            if disco_uso: # Verifica si existen los datos
                datos_utilizacion.append({
                    'fecha': log.fecha,
                    'disco_promedio': disco_uso,
                })
        return datos_utilizacion

    except Exception as e:
        logging.error(f"Error al obtener datos de utilización de recursos: {e}")
        return []

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

app.register_blueprint(auth_bp, url_prefix='/auth') # Registra auth_bp
app.register_blueprint(usuario_bp, url_prefix='/usuarios') # Registra usuario_bp
app.register_blueprint(proceso_bp, url_prefix='/procesos') # Registra proceso_bp
app.register_blueprint(reporte_bp, url_prefix='/reportes') # Registra reporte_bp
app.register_blueprint(log_bp, url_prefix='/logs') # Registra log_bp
app.register_blueprint(tarea_bp, url_prefix='/tareas') # Registra tarea_bp
app.register_blueprint(email_bp, url_prefix='/email') # Registra email_bp

if __name__ == '__main__':
    app.run(debug=True, port=5000) # debug=False en producción