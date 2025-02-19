import argparse
import logging
import os
from app import app, db
from werkzeug.security import generate_password_hash
from sqlalchemy.exc import IntegrityError
import re
# from zxcvbn import zxcvbn  # Si usas zxcvbn para validar contraseñas

app.config['SECRET_KEY'] = 'khadimbamba'  # ¡CAMBIA ESTO!
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://root:@localhost/gestion_recursos'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# Configuración del logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

from app import Usuario

def create_user(usuario, contrasena, confirma_contrasena, email, role):
    with app.app_context():
        try:
            if not usuario or not contrasena or not email:
                raise ValueError("Se requieren nombre de usuario, contraseña y correo electrónico.")
            if contrasena != confirma_contrasena:
                raise ValueError("Las contraseñas no coinciden.")
            if len(contrasena) < 8:
                raise ValueError("La contraseña debe tener al menos 8 caracteres.")
            # resultado = zxcvbn(password)  # Si usas zxcvbn
            # if resultado['score'] < 3:  # Nivel de seguridad de contraseña (ajusta según tus necesidades)
            #     raise ValueError("La contraseña es demasiado débil. Por favor, elija una contraseña más segura.")
            if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
                raise ValueError("El correo electrónico debe tener un formato válido.")

            existing_user = Usuario.query.filter_by(usuario=usuario).first()
            if existing_user:
                logging.info(f"El usuario {usuario} ya existe.")
                return

            existing_email = Usuario.query.filter_by(email=email).first()
            if existing_email:
                logging.info(f"El correo electrónico {email} ya existe.")
                return

            new_user = Usuario(usuario=usuario, contrasena=contrasena, email=email, rol=role)
            db.session.add(new_user)
            db.session.commit()
            logging.info(f"Usuario {usuario} creado con éxito (rol: {role}).")

        except ValueError as ve:
            logging.error(f"Error de validación: {ve}")
            db.session.rollback()
            return
        except IntegrityError as ie:
            logging.error(f"Error de integridad de la base de datos: {ie}")
            db.session.rollback()
            return
        except Exception as e:
            logging.error(f"Error al crear usuario: {e}")
            db.session.rollback()
            return

def create_database_if_not_exists():
    with app.app_context():
        if not os.path.exists('instance/app.db'):  # Ajusta la ruta si es diferente
            db.create_all()
            logging.info("Base de datos creada.")

if __name__ == '__main__':
    create_database_if_not_exists()

    parser = argparse.ArgumentParser(description='Crea un usuario.')
    parser.add_argument('usuario', help='Nombre de usuario')
    parser.add_argument('contrasena', help='Contraseña')
    parser.add_argument('confirma_contrasena', help='Confirmación de la contraseña') # Nueva opción
    parser.add_argument('email', help='Correo electrónico')
    parser.add_argument('--role', help='Rol del usuario (opcional)', default='administrador')  # Permite especificar el rol
    args = parser.parse_args()

    create_user(args.usuario, args.contrasena, args.confirma_contrasena, args.email, args.role)
