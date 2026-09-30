# Chuleta de herramientas · Librería Onuba

El paso a paso

## 0 · Levantar la app

Ejecuta desde la raíz del proyecto. Si no está montada, no funciona

```bash
docker compose up --build
```

La web queda en: `http://localhost:5000`
Swagger UI en: `http://localhost:5000/ui`

Para pararla después:

```bash
docker compose down
```

---

## 1 · Bandit (análisis estático de Python)

Busca fallos en el código sin ejecutarlo. Rápido y sin tocar nada

```bash
docker run --rm -v "$(pwd)/app:/app" ghcr.io/pycqa/bandit/bandit:latest -r /app
```

Resultado: lista de problemas por gravedad (High, Medium, Low)

Útiles:

```bash
# Solo los problemas High y Medium
docker run --rm -v "$(pwd)/app:/app" ghcr.io/pycqa/bandit/bandit:latest -r /app -lll

# Guardar el informe en un archivo
docker run --rm -v "$(pwd)/app:/app" ghcr.io/pycqa/bandit/bandit:latest -r /app -f txt -o informes-bandit.txt

# Marcar en el código con # nosec para que Bandit lo ignore
```

---

## 2 · OWASP ZAP (escaneo dinámico)

Prueba la app en marcha buscando vulnerabilidades

### Opción A · Interfaz gráfica (ZAP Desktop)

1. Abre ZAP Desktop.
2. Colocamos URL
3. Política de escaneo, Dev Full
4. Seleccionamos usar spider tradicional
5. Usar modern spider cliente para spider con firefox si es moderno
6. Le damos atacar, y escanear la app esperamos a que termine
7. Barra de herramientas Seleccionamos Informe --> Generar informe
8. Ponemos la ruta que queramos y Generar Informe

### Opción B · Docker CLI (sin interfaz)

```bash
# Levanta ZAP en el puerto 8090 y escanea la URL
docker run --rm -v "$(pwd):/zap/wrk:rw" -p 8090:8090 \
  ghcr.io/zaproxy/zaproxy:stable zap-full-scan.py \
  -t http://localhost:5000 -r informes/zap-report.html
```

El informe HTML queda en `informes/zap-report.html` dentro del proyecto.

Útiles:

```bash
# Escaneo pasivo (más discreto)
docker run --rm -v "$(pwd):/zap/wrk:rw" ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py -t http://localhost:5000 -r informes/zap-baseline.html
```

---

## 3 · Orden recomendado

1. Arranca la app (`docker compose up --build`).
2. Bandit primero (estático, rápido).
3. ZAP después (dinámico, necesita la app en marcha).
4. Revisa las alertas y márcalas en la tabla de `docs/01-auditoria.md`.