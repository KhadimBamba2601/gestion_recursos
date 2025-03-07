import pytest
from app import db
from app.models import Tarea, ReporteRecurso
from datetime import datetime
import os

def save_response_to_file(response_text, filename):
    with open(f"debug_{filename}.html", "w", encoding="utf-8") as f:
        f.write(response_text)
    print(f"Respuesta guardada en: debug_{filename}.html")

def test_iniciar_sesion(client):
    rv = client.post('/iniciar_sesion', data={
        'nombre_usuario': 'test_admin',
        'contraseña': 'test123'
    }, follow_redirects=True)
    response_text = rv.data.decode('utf-8')
    save_response_to_file(response_text, "login_exitoso")
    assert rv.status_code == 200, f"Login exitoso failed: {response_text[:500]}..."
    assert 'Inicio de sesión exitoso!' in response_text, f"Mensaje no encontrado: {response_text[:500]}..."

    rv = client.post('/iniciar_sesion', data={
        'nombre_usuario': 'test_admin',
        'contraseña': 'wrongpass'
    }, follow_redirects=True)
    response_text = rv.data.decode('utf-8')
    save_response_to_file(response_text, "login_fallido")
    assert rv.status_code == 200, f"Login fallido failed: {response_text[:500]}..."
    assert 'Credenciales inválidas' in response_text, f"Mensaje no encontrado: {response_text[:500]}..."

def test_crear_tarea(login_admin):
    rv = login_admin.post('/crear_tarea', data={
        'nombre': 'monitoreo_sistema',
        'frecuencia': 'diario',
        'hora_ejecucion': '12:00'
    }, follow_redirects=True)
    response_text = rv.data.decode('utf-8')
    save_response_to_file(response_text, "crear_tarea")
    assert rv.status_code == 200, f"Crear tarea failed: {response_text[:500]}..."
    assert 'Tarea creada exitosamente.' in response_text, f"Mensaje no encontrado: {response_text[:500]}..."

    with login_admin.application.app_context():
        tarea = Tarea.query.filter_by(nombre='monitoreo_sistema', usuario_id=1).first()
        assert tarea is not None, "Tarea no encontrada en la base de datos"
        assert tarea.descripcion == 'Monitoreo del sistema'
        assert tarea.frecuencia == 'diario'

def test_generar_reporte(login_admin):
    rv = login_admin.post('/generar_reporte', data={}, follow_redirects=True)
    response_text = rv.data.decode('utf-8')
    save_response_to_file(response_text, "generar_reporte")
    assert rv.status_code == 200, f"Generar reporte failed: {response_text[:500]}..."
    assert 'Reporte generado exitosamente.' in response_text, f"Mensaje no encontrado: {response_text[:500]}..."

    with login_admin.application.app_context():
        reporte = ReporteRecurso.query.filter_by(usuario_id=1).first()
        assert reporte is not None, "Reporte no encontrado en la base de datos"
        assert reporte.cpu >= 0
        assert reporte.tiempo_respuesta >= 0

def test_listar_tareas(login_admin):
    with login_admin.application.app_context():
        tarea = Tarea(
            nombre='list_test',
            descripcion='Prueba listar',
            frecuencia='unica',
            hora_ejecucion='10:00',
            usuario_id=1
        )
        db.session.add(tarea)
        db.session.commit()

    rv = login_admin.get('/tareas?page=1')
    response_text = rv.data.decode('utf-8')
    save_response_to_file(response_text, "listar_tareas")
    assert rv.status_code == 200, f"Listar tareas failed: {response_text[:500]}..."
    # Verificar en la base de datos y en el mensaje flash en lugar de asumir el contenido de la plantilla
    with login_admin.application.app_context():
        tarea = Tarea.query.filter_by(nombre='list_test', usuario_id=1).first()
        assert tarea is not None, "Tarea no encontrada en la base de datos"
    assert 'Lista de tareas cargada exitosamente' in response_text, f"Mensaje flash no encontrado: {response_text[:500]}..."

def test_listar_reportes(login_admin):
    with login_admin.application.app_context():
        reporte = ReporteRecurso(
            cpu=50.0,
            memoria_porcentaje=60.0,
            almacenamiento_porcentaje=70.0,
            tiempo_respuesta=1.0,
            usuario_id=1,
            fecha=datetime.now()
        )
        db.session.add(reporte)
        db.session.commit()

    rv = login_admin.get('/reportes?page=1')
    response_text = rv.data.decode('utf-8')
    save_response_to_file(response_text, "listar_reportes")
    assert rv.status_code == 200, f"Listar reportes failed: {response_text[:500]}..."
   