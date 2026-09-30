# Fase 1 · Informe de auditoría

## Herramientas utilizadas
| Herramienta | Uso | Informe |
|---|---|---|
| OWASP ZAP | Escaneo dinámico y pasivo de la web | [`2026-09-29-ZAP-Report-.html`](2026-09-29-ZAP-Report-.html) |
| Semgrep | Análisis estático del código | `evidencias/ud1/` |
| Bandit | Análisis estático del código Python | Se detectaron 7 problemas (2 medios y 5 bajos) |

## Hallazgos
| ID | Herramienta | Fichero / endpoint | Descripción | Gravedad | CWE / WASC | ¿Falso positivo? Justificación |
|---|---|---|---|---|---|---|
| 01 | ZAP | http://localhost:5000/ui/swagger-ui-bundle.js | Librería JS Vulnerable | Alto | CWE-1395 | No. La librería incluye CVEs conocidos (CVE-2024-48910, CVE-2024-47875, CVE-2025-26791, entre otros) |
| 02 | ZAP | http://localhost:5000/ui/ | Política de seguridad de contenido de Cabecera (CSP) | Medio | CWE-693 / WASC-15 | No. No se envía cabecera CSP en la respuesta |
| 03 | ZAP | http://localhost:5000/ui/ | Falta de cabecera Anti-Clickjacking | Medio | CWE-1021 / WASC-15 | No. No hay X-Frame-Options ni frame-ancestors |
| 04 | ZAP | http://localhost:5000/ui/ | Divulgación de Marcas de Tiempo - Unix | Bajo | CWE-497 / WASC-13 | No. Se filtran marcas de tiempo Unix en varias respuestas |
| 05 | ZAP | http://localhost:5000/ui/favicon-32x32.png | El servidor filtra información por el campo "Server" | Bajo | CWE-497 / WASC-13 | No. Evidencia: `Werkzeug/2.2.3 Python/3.11.16` |
| 06 | ZAP | http://localhost:5000/ui/favicon-32x32.png | Falta cabecera X-Content-Type-Options | Bajo | CWE-693 / WASC-15 | No. Falta nosniff en las respuestas |
| 07 | ZAP | http://localhost:5000/ui/swagger-ui-bundle.js | Revelación de IP privada | Bajo | CWE-497 / WASC-13 | No. Se revela la IP interna `ip-172-31-21-173` de AWS EC2 |
| 08 | ZAP | http://localhost:5000/ui/ | Aplicación Web Moderna | Informativo | - | No es una vulnerabilidad, es informativo |
| 09 | Bandit | app/models/user_model.py:61 | SQL Injection con f-strings en la consulta `get_user` | Medio | CWE-89 | No. Se concatena el usuario dentro de la query SQL |
| 10 | Bandit | app/app.py:8 | La app se expone en 0.0.0.0 con debug activo | Medio | CWE-1327 / CWE-489 | No. `host='0.0.0.0'` y `debug=True` |
| 11 | Bandit | app/config.py:13 | SECRET_KEY demasiado débil valor fijo | Bajo | CWE-798 | No. `SECRET_KEY = 'random'` es fijo y adivinable |
| 12 | Bandit | app/models/user_model.py:73 | Uso de randrange() inseguro para generar el libro | Bajo | CWE-330 | No. Se usa `random.randrange` en vez de `secrets` |
| 13 | Bandit | app/api_views/users.py:84-86 | Tokens vacíos como valor de autorización | Bajo | - | No. Se asigna `auth_token = ''` si falta la cabecera |

## Pruebas


### Documentar test
![alt text](<../evidencias/ud1/Captura de pantalla 2026-09-29 205614.png>)

