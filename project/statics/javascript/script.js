// script.js

document.addEventListener('DOMContentLoaded', () => {

    // 1. Selectores de elementos (clases para mayor flexibilidad)
    const botonAlerta = document.querySelector('.boton-alerta');
    const contenedorMensaje = document.getElementById('contenedor-mensaje');

    // 2. Función para mostrar mensajes (con opciones de tipo, tiempo y cierre manual)
    function mostrarMensaje(mensaje, tipo = 'info', tiempo = 5000) {
        const mensajeElemento = document.createElement('div');
        mensajeElemento.textContent = mensaje;
        mensajeElemento.classList.add('mensaje', `mensaje-${tipo}`);

        contenedorMensaje.appendChild(mensajeElemento);

        // Botón de cierre manual
        const botonCierre = document.createElement('button');
        botonCierre.textContent = '×';
        botonCierre.classList.add('btn-cerrar');
        mensajeElemento.appendChild(botonCierre);

        botonCierre.addEventListener('click', (evento) => {
            evento.stopPropagation(); // Evitar que el clic se propague al mensaje
            mensajeElemento.remove();
        });

        // Cierre automático (opcional)
        if (tiempo > 0) {
            setTimeout(() => {
                mensajeElemento.remove();
            }, tiempo);
        }
    }

    // 3. Función para manejar errores (muestra un mensaje de error y lo registra en la consola)
    function mostrarError(mensaje) {
        console.error(mensaje);
        mostrarMensaje(`Error: ${mensaje}`, 'error');
    }

    // 4. Evento de clic en el botón principal (con manejo de errores y mensaje personalizado)
    if (botonAlerta) {
        botonAlerta.addEventListener('click', () => {
            try {
                // Ejemplo: Simulación de una operación que podría lanzar un error (puedes descomentar para probar)
                // const resultado = miFuncionQuePuedeFallar();
                // if (!resultado) {
                //     throw new Error('La función ha fallado.');
                // }

                mostrarMensaje('¡Hola! Has hecho clic en el botón principal.', 'success'); // Mensaje personalizado
            } catch (error) {
                mostrarError(error.message);
            }
        });
    } else {
        mostrarError('No se encontró el botón principal.');
    }

    // 5. Ejemplo de otros botones (usando un selector más genérico y mensaje dinámico)
    const otrosBotones = document.querySelectorAll('.otro-boton');

    otrosBotones.forEach(boton => {
        boton.addEventListener('click', () => {
            mostrarMensaje(`Clic en botón: ${boton.textContent}`, 'info', 3000); // Mensaje dinámico y cierre automático
        });
    });

    // 6.  Ejemplo de mensaje automático al cargar la página (opcional)
    mostrarMensaje('¡Bienvenido a la página!', 'info', 10000); // Mensaje de bienvenida

});