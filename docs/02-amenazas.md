# Fase 2 · Modelo de amenazas

## Diagrama de flujo de datos
Hecho con OWASP Threat Dragon (exporta la imagen y el JSON a `evidencias/ud2/`).

## Tabla STRIDE

| **Elemento** | **S** | **T** | **R** | **I** | **D** | **E** | **Descripción de la amenaza** |
| ------------ | ----- | ----- | ----- | ----- | ----- | ----- | ----------------------------- |
| PyJWT — mezcla de algoritmos HMAC/asimétricos | X | X |  |  |  | X | Un atacante puede falsificar la firma de un JWT, suplantar a un usuario y obtener privilegios superiores. |
| PyJWT — omisión de verificación de autenticidad | X | X |  |  |  | X | Se pueden aceptar tokens modificados o no válidos, permitiendo acceso como otro usuario. |
| PyJWT — exposición de información sensible |  |  |  | X |  |  | El contenido de un token puede revelar datos de usuario o de sesión a personas no autorizadas. |
| PyJWT — tokens malformados |  |  |  |  | X |  | Los tokens diseñados para provocar fallos pueden consumir recursos y degradar el servicio de autenticación. |
| Werkzeug — depurador vulnerable a CSRF | X | X |  |  |  | X | Un atacante puede abusar de un depurador expuesto para ejecutar comandos y tomar control del servidor. |
| Werkzeug — cargas multipart sin límites |  |  |  |  | X |  | Una carga HTTP muy grande o especialmente preparada puede agotar la memoria o la CPU del servidor. |
| Werkzeug — path traversal y nombres de dispositivo Windows |  | X |  | X |  |  | Rutas manipuladas pueden permitir leer o escribir archivos fuera de la ubicación autorizada. |
| Flask — cookies persistentes y caché de datos sensibles | X |  |  | X |  |  | Una sesión almacenada en una cookie o caché insegura puede ser reutilizada o leída por otra persona. |
| urllib3 — validación TLS incorrecta | X | X |  | X |  |  | Un atacante en la red puede hacerse pasar por un servicio externo e interceptar las comunicaciones. |
| urllib3 — recursos sin límite o bucle en respuestas |  |  |  |  | X |  | Una respuesta HTTP maliciosa puede bloquear hilos y agotar los recursos del proceso cliente. |
| msgpack — uso de memoria liberada en deserialización |  | X |  |  | X |  | Datos serializados manipulados pueden corromper memoria, bloquear el proceso o causar denegación de servicio. |
| setuptools — path traversal y Unicode en instalación |  | X |  |  |  | X | Un paquete manipulado puede sobrescribir archivos durante la instalación y alterar el entorno de compilación. |
| jaraco-context — Zip Slip |  | X |  |  |  | X | Un archivo comprimido malicioso puede extraer archivos fuera del directorio de destino y sobrescribir archivos del sistema. |
| wheel — path traversal en paquetes |  | X |  |  |  | X | Un paquete wheel diseñado por un atacante puede modificar rutas o archivos no autorizados durante su instalación. |
| pip — enlaces y rutas peligrosas |  | X |  |  |  | X | Paquetes, enlaces o rutas manipuladas pueden cambiar archivos del sistema durante la gestión de dependencias. |
| Alpine (zlib) — biblioteca base vulnerable |  | X |  |  | X |  | Datos comprimidos preparados para activar el fallo pueden comprometer la estabilidad del contenedor. |

**Leyenda:** S = suplantación de identidad; T = manipulación; R = repudio; I = divulgación de información; D = denegación de servicio; E = elevación de privilegios.


## Valoración de riesgos — OWASP ASVS L1

### Método

Se aplica la fórmula simplificada de OWASP:

**Riesgo = Probabilidad × Impacto**

| Valor | Probabilidad / impacto |
|---:|---|
| 1 | Bajo |
| 2 | Medio |
| 3 | Alto |

| Resultado | Nivel de riesgo |
|---:|---|
| 1–2 | Bajo |
| 3–4 | Medio |
| 6 | Alto |
| 9 | Crítico |

### Valoración de riesgos

| Amenaza | Probabilidad | Impacto | Riesgo | Justificación |
|---|---:|---:|---:|---|
| PyJWT: falsificación de firma por mezcla de algoritmos HMAC/asimétricos | 3 | 3 | **9 · Crítico** | Un atacante externo puede crear tokens aceptados por la aplicación y suplantar cuentas con privilegios elevados. |
| PyJWT: omisión de verificación de autenticidad en tokens | 3 | 3 | **9 · Crítico** | Un atacante puede modificar o presentar tokens no válidos para acceder como otro usuario. |
| PyJWT: exposición de información sensible en JWT | 2 | 3 | **6 · Alto** | Requiere acceder a un token, pero puede revelar datos de usuario o de sesión a personas no autorizadas. |
| PyJWT: denegación de servicio por tokens malformados | 3 | 2 | **6 · Alto** | Cualquiera que alcance el servicio puede enviar tokens malformados y agotar recursos del componente de autenticación. |
| Werkzeug: abuso del depurador mediante CSRF | 2 | 3 | **6 · Alto** | Exige que el depurador esté activo en producción, pero entonces puede permitir ejecutar código y controlar el servidor. |
| Werkzeug: consumo de recursos en cargas multipart | 3 | 2 | **6 · Alto** | Cualquier cliente puede enviar cargas diseñadas para consumir memoria o CPU y dejar el servicio sin disponibilidad. |
| Flask: cookies persistentes o caché de datos sensibles | 2 | 3 | **6 · Alto** | Precisa acceder al navegador o a una caché compartida, pero puede exponer sesiones y datos personales. |
| urllib3: validación incorrecta de certificados TLS salientes | 2 | 3 | **6 · Alto** | Un atacante situado en la red puede interceptar el tráfico y hacerse pasar por un servicio externo. |
| urllib3: recursos sin límite o bucle infinito en respuestas | 3 | 2 | **6 · Alto** | Un servidor remoto o una respuesta manipulada puede bloquear hilos y agotar recursos del cliente. |
| setuptools: path traversal y manipulación Unicode durante la instalación | 2 | 3 | **6 · Alto** | Requiere un paquete o archivo de distribución manipulado, pero puede sobrescribir archivos fuera del directorio previsto. |
| jaraco-context: Zip Slip al extraer archivos comprimidos | 2 | 3 | **6 · Alto** | Requiere procesar un archivo comprimido malicioso, que puede escribir archivos arbitrarios fuera del destino de extracción. |
| wheel: path traversal en la instalación de paquetes | 2 | 3 | **6 · Alto** | Requiere instalar un paquete malicioso, pero permite modificar rutas o archivos del sistema durante la instalación. |
| pip: path traversal y manejo peligroso de enlaces y archivos | 2 | 3 | **6 · Alto** | Requiere una fuente o paquete manipulado, con capacidad de alterar archivos durante la instalación. |
| Werkzeug: path traversal y nombres de dispositivo Windows | 2 | 2 | **4 · Medio** | Requiere una ruta controlada por el atacante y un entorno afectado, pudiendo leer o escribir archivos no autorizados. |
| msgpack: uso de memoria liberada durante deserialización | 2 | 2 | **4 · Medio** | Requiere datos serializados manipulados; puede provocar bloqueos, corrupción de memoria o denegación de servicio. |
| Alpine (zlib): vulnerabilidad en biblioteca base del sistema | 2 | 2 | **4 · Medio** | Requiere que el contenedor procese datos que activen el fallo; afecta la estabilidad del contenedor y sus procesos. |

La tabla está ordenada de mayor a menor riesgo. La valoración parte de los 16 hallazgos descritos en `analisis-riesgos-asvs-l1-v2.md`.

