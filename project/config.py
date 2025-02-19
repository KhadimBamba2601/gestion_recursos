import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'Khadimbamba'  # Clave secreta para la aplicación
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'mysql://root:@localhost/gestion_recursos'     # URL de la base de datos
    SQLALCHEMY_TRACK_MODIFICATIONS = False  # Desactivar el seguimiento de modificaciones de SQLAlchemy
    