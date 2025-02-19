# Sistema de Gestión de Recursos

Este proyecto es un sistema web para la gestión y monitoreo de recursos del sistema, desarrollado con Flask. Permite a los usuarios autenticados visualizar información del sistema, gestionar usuarios y tareas, y generar reportes en formato PDF o CSV.

## Características

*   **Autenticación de usuarios:** Los usuarios deben iniciar sesión para acceder a las funcionalidades del sistema.
*   **Dashboard:** Panel de control con información general del sistema.
*   **Gestión de usuarios:** Permite crear, editar y eliminar usuarios.
*   **Gestión de tareas:** Permite crear, editar y eliminar tareas.
*   **Generación de reportes:** Permite generar reportes de rendimiento del sistema, tiempos de respuesta y utilización de recursos en formato PDF o CSV, filtrando por rango de fechas.
*   **Monitoreo de recursos:** Permite visualizar información sobre el uso de CPU, memoria y disco.

## Tecnologías utilizadas

*   **Python:** Lenguaje de programación principal.
*   **Flask:** Framework web para el desarrollo de la aplicación.
*   **Flask-Login:** Para la gestión de usuarios y sesiones.
*   **Flask-Mail:** Para el envío de correos electrónicos.
*   **Flask-WTF:** Para la creación de formularios web.
*   **Flask-SQLAlchemy:** Para la interacción con la base de datos (SQL).
*   **psutil:** Para obtener información del sistema (CPU, memoria, disco, etc.).
*   **reportlab:** Para la generación de informes en PDF.
*   **Bootstrap:** Framework CSS para el diseño de la interfaz web.

## Instalación

1.  Clona este repositorio:

    ```bash
    git clone git@github.com:KhadimBamba2601/gestion_recursos.git
    ```

2.  Crea un entorno virtual (recomendado):

    ```bash
    python3 -m venv .venv
    source .venv/bin/activate  # Linux/macOS
    .venv\Scripts\activate  # Windows
    ```

3.  Instala las dependencias:

    ```bash
    pip install -r requirements.txt
    ```

4.  Configura la base de datos:

    *   Asegúrate de tener un servidor de base de datos instalado (por ejemplo, PostgreSQL, MySQL).
    *   Crea una base de datos.
    *   Configura la conexión a la base de datos en el archivo de configuración de Flask (habitualmente `config.py` o un archivo similar).

5.  Configura las credenciales de correo electrónico:

    *   Si utilizas la funcionalidad de envío de correos electrónicos, configura las credenciales en el archivo de configuración.

6.  Ejecuta la aplicación:

    ```bash
    python app.py
    ```

## Uso

1.  Accede a la aplicación en tu navegador: `http://127.0.0.1:5000/`
2.  Regístrate o inicia sesión para acceder a las funcionalidades del sistema.

## Estructura del proyecto

.<br>
├──project
│   ├── app.py          # Archivo principal de la aplicación Flask<br>
│   ├── views.py        # Archivo con las rutas y la lógica de las vistas<br>
│   ├── models.py       # Archivo con la definición de los modelos de la base de datos<br>
│   ├── config.py       # Archivo de configuración<br>
│   ├── create_admin.py #Archivo para crear usuarios de administrador<br>
│   ├── forms.py
│   ├── management.py
│   ├── templates/      # Carpeta con los templates HTML<br>
│   │   ├── base.html<br>
│   │   ├── crear-log.html<br>
│   │   ├── crear-tarea<br>
│   │   ├── crear-usuario<br>
│   │   ├── dashboard.html<br>
│   │   ├── detalle-procesos.html<br>
│   │   ├── detalle-reportes.html<br>
│   │   ├── editar-tarea.html<br>
│   │   ├── editar-usuario.html<br>
│   │   ├── enviar-correo.html<br>
│   │   ├── generar_reporte.html<br>
│   │   ├── index.html<br>
│   │   ├── lista-log.html<br>
│   │   ├── lista-procesos.html<br>
│   │   ├── lista-tarea.html<br>
│   │   ├── lista-usuario.html<br>
│   │   ├── login.html<br>
│   │   └── registro.html<br>
│   ├── static/         # Carpeta con archivos estáticos (CSS, JavaScript)
│   │   ├── css/<br>
│   │   └── styles.css<br>
│   │   ├── javascript/<br>
│   │   └── script.js<br>
│   ├── requirements.txt # Archivo con las dependencias del proyecto<br>
│   ├── Informe.pdf<br>
└── README.md
