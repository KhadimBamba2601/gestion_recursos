# Gestión de Recursos Administrativos

Este proyecto es una aplicación web desarrollada con Flask para la gestión administrativa de recursos del sistema, tareas programadas y reportes. Permite a los usuarios autenticados crear, listar y gestionar tareas, generar reportes de uso de recursos (CPU, memoria, almacenamiento) y administrar usuarios (solo para administradores).

## Características

- **Autenticación:** Inicio de sesión y registro de usuarios con roles (`usuario` y `administrador`).
- **Gestión de Tareas:** Creación, edición, eliminación y listado de tareas programadas con frecuencias (única, diaria, semanal, mensual).
- **Reportes de Recursos:** Generación y listado de reportes sobre el uso del sistema (CPU, memoria, almacenamiento).
- **Administración de Usuarios:** Solo para administradores, incluye creación, edición y eliminación de usuarios.
- **Interfaz Web:** Basada en Bootstrap 5 para una experiencia de usuario responsiva.

## Tecnologías utilizadas

- **Backend:** Python 3, Flask, SQLAlchemy, Flask-Login, APScheduler
- **Frontend:** HTML, Bootstrap 5
- **Base de datos:** SQLite (configurable para otras bases de datos mediante SQLAlchemy)
- **Pruebas:** Pytest

## Requisitos previos

- Python 3.8 o superior
- MySQL
- Git (para clonar el repositorio)
- Un entorno virtual (recomendado)

## Instalación

1. **Clona el repositorio:**<br>
Introduce el siguiente comando en la consola:<br>
   git clone https://github.com/<tu-usuario>/gestion_recursos.git<br>
   cd gestion_recursos<br>
Crea y activa un entorno virtual:<br>
  python -m venv venv<br>
  source venv/bin/activate  # En Windows: venv\Scripts\activate<br>
Instala las dependencias:<br>
  pip install -r requirements.txt<br>

Inicia la aplicación:<br>
Al iniciar la aplicación se crea e inicializa la base de datos.<br>
  python run.py<br>
La aplicación estará disponible en http://127.0.0.1:5000.<br>
## Uso
**Registro e Inicio de Sesión:**<br>
Accede a /registrar para crear un usuario.<br>
Usa /iniciar_sesion para autenticarte (credenciales de prueba: test_admin / test123).<br>
**Gestión de Tareas:**<br>
Ve a /tareas para listar tus tareas.<br>
Usa /crear_tarea para agregar una nueva tarea.<br>
**Reportes:**<br>
Genera un reporte en /generar_reporte.<br>
Lista los reportes en /reportes.<br>
**Administración (solo administradores):**<br>
Gestiona usuarios en /usuarios.<br>
## Estructura del proyecto<br>

gestion_recursos/<br>
├── app/<br>
│   ├── __init__.py         # Configuración de la aplicación Flask<br>
│   ├── models.py           # Modelos de la base de datos (Usuario, Tarea, ReporteRecurso)<br>
│   ├── routes.py           # Rutas de la aplicación<br>
│   ├── templates/          # Plantillas HTML (base.html, lista-tarea.html, etc.)<br>
│   └── utils.py            # Funciones auxiliares (e.g., obtener_recursos_sistema)<br>
├── tests/<br>
│   ├── __init__.py<br>
│   └── test_app.py         # Pruebas unitarias con Pytest<br>
├── requirements.txt        # Dependencias del proyecto<br>
└── README.md               # Este archivo<br>
**Pruebas**<br>
El proyecto incluye pruebas unitarias con Pytest para validar las funcionalidades clave.<br>

Instala las dependencias de prueba:<br>
  pip install pytest<br>
Ejecuta las pruebas:<br>
  pytest --disable-warnings<br>
Esto ejecutará las pruebas en tests/test_app.py, que cubren inicio de sesión, creación de tareas, generación de reportes y listado de tareas/reportes.<br>
Durante las pruebas, se generan archivos debug_*.html en el directorio raíz para inspeccionar las respuestas HTML.
