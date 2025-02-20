CREATE DATABASE gestion_recursos;
USE gestion_recursos;
CREATE TABLE usuarios (
    id INT AUTO_INCREMENT PRIMARY KEY,
    nombre VARCHAR(255) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    contrasena VARCHAR(255) NOT NULL,
    rol ENUM('administrador', 'usuario') NOT NULL,
    fecha_creacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE procesos (
    id INT AUTO_INCREMENT PRIMARY KEY,
    nombre VARCHAR(255) NOT NULL,
    descripcion TEXT,
    estado ENUM('activo', 'inactivo') NOT NULL,
    recursos_consumidos JSON,
    fecha_creacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE tareas (
    id INT AUTO_INCREMENT PRIMARY KEY,
    nombre VARCHAR(255) NOT NULL,
    descripcion TEXT,
    frecuencia VARCHAR(255) NOT NULL,
    fecha_ejecucion DATETIME,
    estado ENUM('pendiente', 'en_progreso', 'completada', 'fallida') NOT NULL,
    fecha_creacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    fecha TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    nivel ENUM('info', 'warning', 'error') NOT NULL,
    mensaje TEXT NOT NULL
);
CREATE TABLE usuarios_tareas (
    usuario_id INT,
    tarea_id INT,
    FOREIGN KEY (usuario_id) REFERENCES usuarios(id),
    FOREIGN KEY (tarea_id) REFERENCES tareas(id),
    PRIMARY KEY (usuario_id, tarea_id) -- Clave primaria compuesta
);
ALTER TABLE tareas
ADD COLUMN usuario_id INT,
ADD FOREIGN KEY (usuario_id) REFERENCES usuarios(id);