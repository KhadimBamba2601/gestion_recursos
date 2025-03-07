import pytest
from app import app as flask_app, db
from app.models import Usuario
import os
import tempfile

@pytest.fixture
def app():
    db_fd, db_path = tempfile.mkstemp(suffix='.db')
    flask_app.config['TESTING'] = True
    flask_app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
    flask_app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    flask_app.config['WTF_CSRF_ENABLED'] = False  # Desactivar CSRF para simplificar pruebas
    
    with flask_app.app_context():
        db.drop_all()
        db.create_all()
        test_admin = Usuario(
            nombre_usuario='test_admin',
            correo='test_admin@ejemplo.com',
            rol='administrador',
            nombre='Test',
            apellido='Admin'
        )
        test_admin.establecer_contraseña('test123')
        db.session.add(test_admin)
        db.session.commit()
    
    yield flask_app
    
    with flask_app.app_context():
        db.session.remove()
        db.drop_all()
    os.close(db_fd)
    os.unlink(db_path)

@pytest.fixture
def client(app):
    return app.test_client()

@pytest.fixture
def login_admin(client, app):
    with app.app_context():
        rv = client.post('/iniciar_sesion', data={
            'nombre_usuario': 'test_admin',
            'contraseña': 'test123'
        }, follow_redirects=True)
        assert rv.status_code == 200, f"Login failed: {rv.data.decode('utf-8')}"
        yield client