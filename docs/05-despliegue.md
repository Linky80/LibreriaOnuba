# Fase 5 · Despliegue

## Flujo de trabajo en el repositorio
* **Ramas:** `main` como rama base y ramas de trabajo/fase (como `JosecdrFase1` o ramas cortas tipo `feat/...` o `fix/...`) para ir metiendo cambios sin romper lo estable.
* **Protección de la rama principal:** nada de `push` directo a `main` ni *force-push* a lo loco; los cambios entran por *Pull Request* cuando pasan las comprobaciones automáticas.
* **Revisiones obligatorias:** al menos una revisión antes de fusionar, para que se revise bien el código y no se cuelen secretos, fallos gordos ni archivos basura (`DS_Store`, temporales, etc.).

## Pipeline CI/CD
El pipeline se lanza solo en cada *Pull Request* o *push* a la rama principal; si cualquier paso casca, se frena ahí y no pasa al siguiente:

1. **Lint y análisis estático (SAST / dependencias):** revisa estilo/sintaxis, análisis de código (como Bandit) y vulnerabilidades de paquetes/dependencias (como `pip-audit`) antes de seguir.
2. **Build:** comprueba que el proyecto y su contenedor/imagen montan sin errores y que las dependencias instalan bien.
3. **Tests:** ejecuta las pruebas automáticas para verificar que la API y sus endpoints siguen respondiendo como toca.
4. **Empaquetado:** genera la imagen del contenedor lista y etiquetada para desplegar.
5. **Despliegue:** solo si todo lo anterior sale en verde, actualiza el servicio con la nueva versión.

## Despliegue y tolerancia a fallos
* **Cómo se despliega:** despliegue automatizado al aprobar/mezclar en la rama objetivo, levantando el contenedor/servicio con variables de entorno bien configuradas (nada de meter claves o secretos a pelo en el repo).
* **Healthchecks:** comprobación de salud (endpoint de estado o comprobación del contenedor/puerto y base de datos) para confirmar que arranca bien y responde de verdad antes de dar el despliegue por bueno.
* **Reinicios:** política de reinicio automático del contenedor/servicio si falla o se cae, junto con límites de recursos para que un pico no tumbe el host.
* **Vuelta atrás:** si tras desplegar algo revienta o falla el *healthcheck*, vuelta rápida a la versión/imagen anterior estable y revisión de logs para ver qué ha pasado.