import psutil
import mysql.connector
import schedule
import time
import datetime
import logging
import os
import subprocess
from fpdf import FPDF
import pandas as pd
import matplotlib.pyplot as plt

# Configuración del logging (se mantiene aquí)
logging.basicConfig(filename="management.log", level=logging.INFO,
                    format="%(asctime)s - %(levelname)s - %(message)s")

# Configuración de la base de datos MySQL (usar variables de entorno - se mantiene aquí)
DB_HOST = os.environ.get("DB_HOST")
DB_USER = os.environ.get("DB_USER")
DB_PASSWORD = os.environ.get("DB_PASSWORD")
DB_NAME = os.environ.get("DB_NAME")

try:
    mydb = mysql.connector.connect(
        host=DB_HOST,
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME
    )
except mysql.connector.Error as err:
    logging.error(f"Error al conectar a la base de datos: {err}")
    exit(1)

# --- Módulo de monitorización ---
def monitor_cpu():
    try:
        cpu_percent = psutil.cpu_percent(interval=1)
        if cpu_percent > 80:
            logging.warning("Sobrecarga de CPU detectada.")
            return True  # Indica sobrecarga
        return False
    except Exception as e:
        logging.error(f"Error al monitorizar CPU: {e}")
        return False

def monitor_memoria():
    try:
        mem_percent = psutil.virtual_memory().percent
        if mem_percent > 80:
            logging.warning("Sobrecarga de memoria detectada.")
            return True
        return False
    except Exception as e:
        logging.error(f"Error al monitorizar memoria: {e}")
        return False

def monitor_disco():
    try:
        disk_percent = psutil.disk_usage('/').percent
        if disk_percent > 80:
            logging.warning("Sobrecarga de disco detectada.")
            return True
        return False
    except Exception as e:
        logging.error(f"Error al monitorizar disco: {e}")
        return False

def monitor_procesos():
    try:
        for proc in psutil.process_iter(['name', 'cpu_percent']):
            if proc.info()['cpu_percent'] > 50:
                logging.warning(f"Proceso ineficiente detectado: {proc.info()['name']}")
    except Exception as e:
        logging.error(f"Error al monitorizar procesos: {e}")

# --- Módulo de tareas programadas ---
def respaldar_base_datos():
    try:
        now = datetime.datetime.now()
        timestamp = now.strftime("%Y-%m-%d_%H-%M-%S")
        filename = f"backup_{timestamp}.sql"
        # Usar subprocess.run para mayor seguridad
        subprocess.run(["mysqldump", "-u", DB_USER, f"-p{DB_PASSWORD}", DB_NAME, ">", filename], shell=False, check=True)
        logging.info(f"Copia de seguridad de la base de datos creada: {filename}")
    except subprocess.CalledProcessError as e:
        logging.error(f"Error al respaldar la base de datos: {e}")
    except Exception as e:
        logging.error(f"Error inesperado al respaldar la base de datos: {e}")

def limpiar_logs():
    try:
        # Lógica para limpiar logs (ejemplo: eliminar archivos antiguos)
        # ...
        logging.info("Logs limpiados.")
    except Exception as e:
        logging.error(f"Error al limpiar logs: {e}")

def actualizar_software():
    try:
        # Lógica para actualizar software
        # ...
        logging.info("Software actualizado.")
    except Exception as e:
        logging.error(f"Error al actualizar software: {e}")

# --- Módulo de informes ---
def generar_informes():
    try:
        mycursor = mydb.cursor()
        mycursor.execute("SELECT * FROM tabla_de_datos")  # Reemplazar con tu consulta
        data = mycursor.fetchall()

        # Crear DataFrame con pandas
        df = pd.DataFrame(data, columns=[i[0] for i in mycursor.description])

        # Crear informe en PDF con pandas y matplotlib
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", size=12)
        pdf.cell(200, 10, txt="Informe de rendimiento", ln=1, align="C")

        # Ejemplo de gráfico (adaptar a tus datos)
        plt.plot(df['columna1'], df['columna2'])  # Reemplazar con tus columnas
        plt.savefig("grafico.png")
        pdf.image("grafico.png", x=10, y=50, w=180)

        pdf.output("informe.pdf")

        # Exportar a CSV
        df.to_csv("informe.csv", index=False)

        logging.info("Informes generados.")
    except Exception as e:
        logging.error(f"Error al generar informes: {e}")

# --- Tareas programadas ---
schedule.every(10).minutes.do(monitor_cpu)
schedule.every(10).minutes.do(monitor_memoria)
schedule.every(10).minutes.do(monitor_disco)
schedule.every(10).minutes.do(monitor_procesos)
schedule.every().day.at("02:00").do(respaldar_base_datos)
schedule.every().day.at("03:00").do(limpiar_logs)
schedule.every().day.at("04:00").do(actualizar_software)
schedule.every().day.at("05:00").do(generar_informes)

# --- Bucle principal ---
def main():
    while True:
        schedule.run_pending()
        time.sleep(1)

if __name__ == "__main__":
    main()