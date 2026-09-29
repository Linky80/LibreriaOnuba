# Fase 1 · Informe de auditoría

## Herramientas utilizadas
Semgrep, Bandit, OWASP ZAP… (informes en `evidencias/ud1/`).

## Hallazgos
| ID | Herramienta | Fichero / endpoint | Descripción | Gravedad | ¿Falso positivo? Justificación |
|---|---|---|---|---|---|
| 01 | ZAP | http://localhost:5000/ui/swagger-ui-bundle.js | Librería JS Vulnerable | Alto | No |
| 02 | ZAP | http://localhost:5000/ui/ | Política de seguridad de contenido de Cabecera (CSP) | Medio | No |
| 03 | ZAP | http://localhost:5000/ui/ | Falta de cabecera Anti-Clickjacking | Medio | No |
| 04 | ZAP | http://localhost:5000/ui/swagger-ui-standalone-preset.js | Divulgación de Marcas de Tiempo - Unix | Bajo | No |
| 05 | ZAP | http://localhost:5000/ui/favicon-32x32.png | El servidor filtra de información a través del campo "Server" del respuesta HTTP | Bajo | No |
| 06 | ZAP | http://localhost:5000/ui/favicon-32x32.png | Falta border X-Content-Type-Options | Bajo | No |
| 07 | ZAP | http://localhost:5000/ui/swagger-ui-bundle.js | Revelación de IP privada | Bajo | No |
| 08 | ZAP | http://localhost:5000/ui/ | Aplicación Web Moderna | Informativo | No |

## Pruebas
Qué tests habéis escrito en `tests/`, qué comprueba cada uno y cuáles fallan (y por qué).

## Conclusiones
