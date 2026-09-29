# Proyecto «Librería Onuba»

**Módulo:** Puesta en producción segura (05023) · Curso de Especialización en Ciberseguridad en Entornos de las TI · IES La Marisma · 2026/2027

**Pareja:** _nombre y apellidos_ · _nombre y apellidos_

---

## El encargo

La **Librería Onuba** es una librería online de Huelva (ficticia). Sus clientes se registran, inician sesión y gestionan su biblioteca de libros a través de una **API REST**. Cada libro guarda un contenido privado que solo debe ver su propietario.

La librería ha sufrido un incidente de seguridad y os contrata como equipo de seguridad. Durante todo el curso vais a:

1. **Auditar** la aplicación tal como está.
2. **Decidir** qué nivel de seguridad necesita y qué requisitos debe cumplir.
3. **Corregir** sus fallos y **bastionar** el servidor.
4. **Analizar** la app móvil que un proveedor externo ha hecho para la librería.
5. **Desplegarla** de forma automática y segura.

No vais a programar la aplicación desde cero: está en la carpeta `app/` y **tiene fallos de seguridad a propósito**. Vuestro trabajo es encontrarlos, entenderlos y resolverlos.

> ⚠️ **Uso ético.** Esta aplicación es vulnerable. Levántala solo en tu máquina o en la red del laboratorio, nunca expuesta a Internet. Las pruebas de seguridad se hacen únicamente contra las máquinas del laboratorio.

---

## Cómo arrancar la aplicación

Necesitas Docker y Docker Compose.

```bash
docker compose up -d --build
```

- API: <http://localhost:5000>
- Documentación interactiva (Swagger UI): <http://localhost:5000/ui/>
- La primera vez, crea la base de datos con usuarios y libros de prueba: <http://localhost:5000/createdb>

Para pararla: `docker compose down`.

### Sin Docker (alternativa)

```bash
cd app
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

---

## Estructura del repositorio

| Carpeta | Qué contiene |
|---|---|
| `app/` | Código de la API de la librería (Python / Flask). |
| `docs/` | Informes de cada fase. Ya tenéis una plantilla para cada uno. |
| `tests/` | Pruebas automáticas con `pytest`. |
| `evidencias/` | Informes de herramientas y capturas, una carpeta por unidad. |
| `infra/` | Configuración de servidor (Nginx, TLS…), a partir de la fase 3. |

---

## Las cinco fases

Cada fase se marca con una **etiqueta** (tag) en el repositorio y se entrega en la **tarea de Moodle** de esa fase, en la sesión indicada. Lo que se evalúa es lo entregado en Moodle.

| Fase | Unidad | RA | Qué se entrega | Etiqueta | Sesión |
|---|---|---|---|---|---|
| 1. Auditoría inicial | UD1 | RA1 | `docs/01-*`, tests y evidencias de la UD1 | `e1-auditoria` | 10 |
| 2. Perfil de seguridad | UD2 | RA2 | `docs/02-*` (amenazas, nivel ASVS y matriz de requisitos) | `e2-perfil` | 21 |
| 3. Corrección y bastionado | UD3 | RA3 | Código corregido, `infra/`, tests y `docs/03-*` | `e3-bastionado` | 36 |
| 4. Canal móvil | UD4 | RA4 | `docs/04-*` y validación de compras en el servidor | `e4-movil` | 46 |
| 5. Producción DevSecOps | UD5 | RA5 | Pipeline CI/CD, despliegue y `docs/05-*` | `e5-devsecops` | 58 |

### Cómo entregar una fase

1. Comprueba que todo está subido: `git status` debe decir *nothing to commit*.
2. Crea la etiqueta de la fase y súbela:

```bash
git tag e1-auditoria
git push origin e1-auditoria
```

3. En GitHub, cambia `main` por la etiqueta (selector de rama → pestaña **Tags**) → botón **Code** → **Download ZIP**.
4. Sube ese ZIP a la tarea de la fase en **Moodle** y pega el enlace al repositorio.
5. En clase, defensa corta: preguntas a cada miembro sobre lo entregado.

**Si una fase no sale como esperabais**, el profesor publicará una versión de referencia para que la siguiente fase arranque desde un punto limpio.

---

## Normas de trabajo

- Los dos miembros de la pareja hacen commits con su propio usuario.
- Mensajes de commit claros: qué se cambia y por qué.
- En cada entrega, el profesor hará preguntas cortas a cada miembro sobre lo entregado. Lo que no sepas explicar no cuenta como tuyo.
- Desde la fase 5, todo cambio entra por *pull request* revisada por el otro miembro.

---

## Créditos

La aplicación de `app/` está basada en **VAmPI** (© 2020 erev0s), publicada con licencia MIT. Ver `LICENSE-VAmPI.txt`.
