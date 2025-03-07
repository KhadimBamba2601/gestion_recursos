from app import app, db, create_database, routes
from app.models import Usuario

if __name__ == '__main__':
    with app.app_context():
        create_database()  # Crear la base de datos
        db.create_all()    # Crear las tablas
        # Verificar y crear usuario administrador
        admin = Usuario.query.filter_by(rol='administrador').first()
        if not admin:
            admin = Usuario(nombre_usuario='admin', correo='admin@ejemplo.com', rol='administrador', nombre='Admin', apellido='Principal')
            admin.establecer_contraseña('admin123')
            db.session.add(admin)
            db.session.commit()
            print("Usuario administrador 'admin' creado con contraseña 'admin123'.")
        routes.inicializar_tareas()  # Inicializar tareas programadas
    app.run(debug=True)  # Iniciar la aplicación