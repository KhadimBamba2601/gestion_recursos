import psutil
import time

def obtener_recursos_sistema():
    inicio = time.time()
    cpu = psutil.cpu_percent(interval=1)
    memoria = psutil.virtual_memory().percent
    almacenamiento = psutil.disk_usage('/').percent
    fin = time.time()
    tiempo_respuesta = fin - inicio  # Tiempo en segundos
    return {
        'cpu': cpu,
        'memoria_porcentaje': memoria,
        'almacenamiento_porcentaje': almacenamiento,
        'tiempo_respuesta': tiempo_respuesta
    }