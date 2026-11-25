# Fase 5 · Retrospectiva del equipo

## Qué ha funcionado bien

- Docker Compose levanta la API con un solo comando
- ZAP Bandit y pip-audit encontraron los fallos rápido
- Threat Dragon ayudó a ordenar las amenazas
- Las evidencias quedaron agrupadas por unidad
- Los tests avisaron cuando algo se rompió

## Qué mejoraríamos

- Se colaron archivos basura en el repo
- Los informes quedaron dispersos por el proyecto
- La API sigue arrancando con debug activado
- infra/ está vacía y faltan Nginx y TLS
- Varias dependencias tienen CVEs conocidas

## Acciones para la próxima vez

- Revisar git status antes de cada commit
- Guardar todos los informes en evidencias/
- Añadir .DS_Store y venv al .gitignore
- Terminar el bastionado y las copias de seguridad
- Montar el pipeline CI con análisis de dependencias
