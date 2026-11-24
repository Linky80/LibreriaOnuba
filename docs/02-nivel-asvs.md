# Fase 2 · Nivel de verificación ASVS
## Qué es ASUS
ASVS significa Application Security Verification Standard.

Es un estándar de requisitos para diseñar, desarrollar y evaluar la seguridad de aplicaciones. Sirve como lista de verificación para revisar aspectos como autenticación, control de acceso, gestión de sesiones, validación de entradas, criptografía y registro de eventos.

Lo publica OWASP (Open Worldwide Application Security Project), una organización internacional sin ánimo de lucro centrada en mejorar la seguridad del software.

## Nivel elegido
El presente informe analiza la clasificación y mapeo técnico de un conjunto de dieciséis riesgos y vulnerabilidades identificadas en bibliotecas y componentes clave del ecosistema Python (PyJWT, Werkzeug, Flask, urllib3, msgpack, setuptools, jaraco-context, wheel, pip) y la imagen base Alpine. El análisis se contextualiza en la arquitectura del **Estándar de Verificación de Seguridad en Aplicaciones (OWASP ASVS versión 4.0.3)**, justificando su encuadre en el **Nivel 1 (L1)** a partir del tipo de datos procesados, los usuarios y entornos afectados, y el impacto potencial de un incidente.

---

## 1. Encuadre Estratégico en la Estructura de Niveles de ASVS

El estándar OWASP ASVS organiza los requisitos de seguridad en tres niveles progresivos de verificación:
*   **Nivel 1 (L1) - Primeros Pasos y Línea Base:** Orientado a defender las aplicaciones contra vulnerabilidades conocidas, fáciles de descubrir y de explotar. Es el único nivel diseñado para ser comprobable mediante análisis dinámico (DAST), escaneos automatizados de dependencias o pruebas externas de penetración sin acceso obligatorio al código fuente.
*   **Nivel 2 (L2) - Aplicaciones Estándar:** Dirigido a la mayoría de las aplicaciones comerciales que manejan datos confidenciales o ejecutan funciones de negocio críticas, requiriendo revisión de código fuente y arquitectura.
*   **Nivel 3 (L3) - Alta Garantía:** Reservado para aplicaciones críticas (infraestructura crítica, sector bancario, salud) con análisis riguroso de arquitectura y defensa en profundidad.

### Razón Principal de Clasificación en Nivel 1

Todas las amenazas analizadas corresponden a **vulnerabilidades públicas conocidas (CVEs)** en bibliotecas de terceros o componentes del entorno de ejecución. 

En la arquitectura de ASVS, el capítulo **V14 (Configuración)**, y en particular la sección **V14.2 (Dependencias)**, establece en el requisito **14.2.1** la obligación estricta de *"Verificar que todos los componentes estén actualizados, preferiblemente utilizando un comprobador de dependencias en tiempo de compilación"*. Este control es un requisito de cumplimiento obligatorio desde el **Nivel 1 (L1)** para cualquier tipo de aplicación.

---

## 2. Matriz de Mapeo Detallado de Riesgos, Contexto Operativo y ASVS

La siguiente matriz integra el análisis del **tipo de datos**, los **usuarios o entorno afectado** y el **impacto del incidente** para cada una de las 16 amenazas reportadas, vinculándolas con su requisito exacto en ASVS v4.0.3.

| Componente | Amenaza / Vulnerabilidad | Tipo de Datos Manejados | Usuarios / Entorno Afectado | Impacto del Incidente | Requisito Exacto ASVS v4.0.3 | Nivel Mínimo |
| :--- | :--- | :--- | :--- | :--- | :--- | :---: |
| **PyJWT** | Falsificación de firma por mezcla de algoritmos HMAC/Asimétricos | Tokens JWT, declaraciones (*claims*) e identidades de usuario | Usuarios autenticados y APIs públicas | **Crítico:** Suplantación de identidad y escalada de privilegios sin clave secreta | **14.2.1** (Actualización) / **3.5.3** (Verificación criptográfica de tokens) | L1 / L2 |
| **PyJWT** | Omisión de verificación de autenticidad en tokens | Tokens de sesión sin estado y claves de autorización | Clientes de API y microservicios | **Alto:** Aceptación de tokens no válidos o alterados por terceros | **14.2.1** (Actualización) / **3.5.3** (Protección de tokens sin estado) | L1 / L2 |
| **PyJWT** | Exposición de información sensible | *Payloads* de JWT con datos de usuario o parámetros de sesión | Usuarios finales de la aplicación | **Alto:** Fuga de información confidencial hacia usuarios no autorizados | **14.2.1** (Actualización) / **8.2.2** (Datos sensibles en almacenamiento) | L1 |
| **PyJWT** | Denegación de servicio y fallos de robustez | Peticiones con tokens malformados | Servidores web y servicios de autenticación | **Medio:** Inestabilidad en el servicio y consumo excesivo de CPU | **14.2.1** (Actualización) / **11.1.4** (Controles anti-DoS) | L1 |
| **Werkzeug** | Abuso del depurador mediante CSRF | Comandos del depurador y variables de entorno del servidor | Servidores en producción con depuración activa | **Alto / Crítico:** Ejecución Remota de Código (RCE) y control total del servidor | **4.2.2** (Protección anti-CSRF) / **14.3.2** (Depuración deshabilitada) | L1 |
| **Werkzeug** | Consumo descontrolado de recursos en cargas multipart | Cuerpos de peticiones HTTP, cargas de archivos y *buffers* | Servidores backend y peticiones entrantes | **Alto:** Exhaustión de memoria/CPU y Denegación de Servicio (DoS) | **12.1.1** (Límites de tamaño de archivo anti-DoS) | L1 |
| **Werkzeug** | Path traversal y nombres de dispositivo Windows | Nombres de rutas de archivos y parámetros de URL | Servidores que procesan rutas de archivos (Windows) | **Medio:** Lectura o escritura no autorizada en archivos del sistema | **12.3.1** (Validación anti-path traversal) | L1 |
| **Flask** | Cookies persistentes y caché con datos sensibles | Cookies de sesión y respuestas HTTP con datos de usuario | Navegadores de usuario y cachés intermedias | **Alto:** Exposición de sesiones en equipos compartidos o caché | **3.4.1–3.4.3** (Cookies seguras) / **8.2.1** (Headers anti-caché) | L1 |
| **urllib3** | Validación incorrecta de certificados TLS salientes | Tráfico de red cifrado saliente y tokens de API externas | Servicios cliente que consumen APIs externas | **Alto:** Ataques Man-in-the-Middle (MitM) y suplantación de servidor | **9.1.1** (Uso de TLS) / **9.2.1** (Validación de certificados) | L1 |
| **urllib3** | Recursos sin límite y bucle infinito en respuestas | Flujos de respuestas HTTP entrantes | Procesos cliente y conectores HTTP | **Alto:** Bloqueo de hilos de ejecución y agotamiento de recursos | **14.2.1** (Actualización) / **11.1.4** (Límites contra consumo excesivo) | L1 |
| **msgpack** | Uso de memoria liberada durante deserialización | Estructuras de datos serializadas binarias | Microservicios e intercambio de mensajes IPC | **Alto:** Corrupción de memoria, fallos de segmentación y DoS | **5.5.3** (Deserialización segura en librerías) | L1 |
| **setuptools** | Path traversal y manipulación Unicode en instalación | Nombres de paquetes, archivos de distribución `.whl`/`.tar.gz` | Pipelines de CI/CD y entornos de desarrollo | **Alto:** Sobrescritura no autorizada de archivos durante la instalación | **12.3.1** (Protección contra traversal) / **14.2.1** (Actualización) | L1 |
| **jaraco-context**| Zip Slip al extraer archivos comprimidos manipulados | Archivos de archivos comprimidos (ZIP / Tarballs) | Entornos de construcción e instalación de paquetes | **Alto:** Sobrescritura arbitraria de archivos fuera del directorio de destino | **12.1.2** (Verificación de descompresión) / **12.3.1** (Path traversal) | L1 / L2 |
| **wheel** | Path traversal en instalación de paquetes | Metadatos y estructuras de paquetes de Python | Entornos de instalación y compilación de dependencias | **Alto:** Modificación no autorizada de rutas del sistema durante `pip install` | **12.3.1** (Validación de nombres de ruta) / **14.2.1** (Actualización) | L1 |
| **pip** | Path traversal y manejo peligroso de enlaces y archivos | Enlaces simbólicos, paquetes PyPI y rutas de instalación | Gestor de paquetes `pip` en entornos dev/prod | **Medio / Alto:** Manipulación inescrupulosa de archivos en el sistema gestor | **12.3.1** (Validación de metadatos de rutas) / **14.2.1** (Actualización) | L1 |
| **Alpine (zlib)** | Vulnerabilidad de biblioteca base del sistema operativo | Datos comprimidos por el SO y procesos de contenedor | Contenedores en ejecución y sistema operativo host | **Alto:** Compromiso de estabilidad de contenedor y vulnerabilidad de librería base | **14.2.1** (Componentes actualizados) / **14.1.3** (Hardenización) | L1 |

---

## 3. Justificación Detallada según Factores de Evaluación

Para comprender el encuadre en **Nivel 1 (L1)**, cada riesgo se evalúa a la luz de los tres factores operativos:

### A. Tipo de Datos Manejados
1.  **Datos de Sesión e Identidad (PyJWT, Flask):** La alteración de firmas o cookies expone la integridad de las credenciales y tokens de acceso.
2.  **Tráfico de Red y Comunicaciones (urllib3):** Las respuestas y certificados afectan la confidencialidad del tráfico cifrado en tránsito.
3.  **Archivos del Sistema y Empaquetamiento (Werkzeug, setuptools, wheel, pip, jaraco-context):** La inclusión de caracteres de control o `..` manipula la estructura del sistema de archivos.
4.  **Estructuras de Memoria y Datos Binarios (msgpack, Alpine/zlib):** Manejan memoria bruta y buffers comprimidos, donde fallos de manejo causan corrupción o bloqueo.

### B. Usuarios y Entorno Afectado
*   **Usuarios Externos / Públicos:** Expuestos a fallas en PyJWT, Flask y Werkzeug (cargas multipart) que afectan la capa web.
*   **Servicios Backend / APIs Salientes:** Aficados por fallas en urllib3 y msgpack en la comunicación entre microservicios.
*   **Entornos de Compilación y CI/CD:** Afectados por vulnerabilidades en pip, wheel, setuptools y jaraco-context durante el despliegue e instalación de dependencias.

### C. Impacto del Incidente
*   **Confidencialidad:** Fuga de tokens de sesión (Flask, PyJWT) e interceptación de tráfico saliente (urllib3).
*   **Integridad:** Alteración arbitraria de archivos por *path traversal* (setuptools, wheel, jaraco-context) o suplantación de identidad (PyJWT).
*   **Disponibilidad:** Bloqueo de servicios o agotamiento de recursos (Werkzeug multipart, urllib3, msgpack).

---

## 4. Análisis Técnico por Dominio de Seguridad

### A. Gestión de Dependencias y Componentes de Terceros (Capítulo V14)
El hallazgo central radica en que todas las amenazas corresponden a defectos en la cadena de suministro de software (*Software Supply Chain*). 

ASVS exige en el requisito **14.2.1** que las aplicaciones mantengan todos sus componentes actualizados. En un canal de integración continua (CI/CD), la detección de cualquiera de estos CVEs mediante herramientas de Software Composition Analysis (SCA) constituye un fallo de conformidad con la línea base de Nivel 1. 

Para aplicaciones que aspiren al **Nivel 2 (L2)** o **Nivel 3 (L3)**, la gestión de estas dependencias se profundiza exigiendo la generación automática de una Lista de Materiales de Software (SBOM, requisito **14.2.5**) y el aislamiento o encapsulamiento (*sandboxing*) de las bibliotecas de terceros para exponer únicamente el comportamiento necesario (requisito **14.2.6**).

### B. Manipulación de Archivos y Recursos (Capítulo V12)
Las vulnerabilidades de *Path Traversal* (*Werkzeug, setuptools, wheel, pip*) y *Zip Slip* (*jaraco-context*) vulneran directamente los principios del control de archivos:
*   El requisito **12.3.1** impone en **Nivel 1** que los metadatos de nombres de archivo o rutas enviados por el usuario o paquetes no se utilicen directamente en el sistema de archivos sin una API o validación que impida la navegación fuera del directorio destino.
*   El requisito **12.1.1** exige definir límites explícitos para evitar el agotamiento de recursos o ataques de Denegación de Servicio (DoS) por archivos de gran tamaño.

### C. Configuración, CSRF y Modos de Depuración (Capítulos V4 y V14)
El riesgo asociado al depurador de Werkzeug expone una falla crítica de configuración:
*   El requisito **14.3.2** exige en **Nivel 1** que los modos de depuración e interfaces de desarrollo estén strictly deshabilitados en entornos de producción.
*   Si la consola interactiva queda expuesta y carece de token o protección anti-CSRF, se vulnera además el requisito **4.2.2** sobre la obligatoriedad de mecanismos de protección contra la Falsificación de Solicitudes entre Sitios.

### D. Comunicaciones Inseguras y TLS (Capítulo V9)
La validación incorrecta de certificados salientes en *urllib3* afecta la seguridad del transporte:
*   El requisito **9.1.1** exige la aplicación de TLS para toda conectividad, mientras que el requisito **9.2.1** exige que el cliente o servidor verifique la autenticidad de los certificados mediante CAs de confianza, previniendo ataques de tipo *Man-in-the-Middle* (MitM).

### E. Deserialización y Gestión de Memoria (Capítulo V5)
La vulnerabilidad en *msgpack* vinculada al uso de memoria liberada durante la deserialización se enmarca en la sección V5.5:
*   El requisito **5.5.3** exige en **Nivel 1** la protección contra la deserialización de datos no confiables tanto en código personalizado como en bibliotecas de terceros.

---

## 5. Conclusiones y Plan de Remediación

1.  **Nivel de Cumplimiento:** Todos los riesgos analizados corresponden a la **línea base de Nivel 1 (L1)** de OWASP ASVS. La presencia de cualquiera de estos CVEs impide que la aplicación certifique el Nivel 1 y, por naturaleza jerárquica y acumulativa del estándar, invalida también el cumplimiento de los Niveles 2 y 3.
2.  **Estrategia de Corrección Inmediata (L1):** 
    *   Actualizar de forma prioritaria las versiones de las bibliotecas afectadas en el archivo de requerimientos (`requirements.txt` / `Pipfile` / `pyproject.toml`).
    *   Reconstruir la imagen de contenedor base de Alpine aplicando las actualizaciones de paquetes del sistema operativo (`apk upgrade`).
3.  **Fortalecimiento Institucional (L2/L3):**
    *   Integrar un analizador de dependencias (SCA) en el pipeline de compilación automatizada conforme al requisito **14.1.1**.
    *   Asegurar que los entornos de producción tengan deshabilitado el modo de depuración (`FLASK_ENV=production`, `DEBUG=False`).
    *   Implementar un inventario SBOM para rastrear el ciclo de vida de componentes de terceros.

