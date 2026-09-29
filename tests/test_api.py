"""Pruebas de la API de la Librería Onuba.

Ejecutar con la API levantada:
    pip install pytest requests
    pytest -v

Hay dos tipos de prueba:
- Funcionales: comprueban que la aplicación hace lo que debe. Deben pasar siempre.
- De seguridad: comprueban que la aplicación NO hace lo que no debe.
  Con la aplicación sin corregir fallan; en la fase 3 tienen que pasar.
"""
import os

import pytest
import requests

BASE = os.getenv("API_URL", "http://localhost:5000")


@pytest.fixture(scope="session", autouse=True)
def base_de_datos():
    requests.get(f"{BASE}/createdb", timeout=10)


# ---------- Funcionales ----------

def test_home_responde():
    r = requests.get(f"{BASE}/", timeout=10)
    assert r.status_code == 200


def test_listado_de_libros():
    r = requests.get(f"{BASE}/books/v1", timeout=10)
    assert r.status_code == 200
    assert "Books" in r.json()


# ---------- Seguridad ----------

def test_login_no_revela_si_el_usuario_existe():
    """El mensaje de error debe ser el mismo tanto si el usuario existe como si no."""
    existe = requests.post(f"{BASE}/users/v1/login",
                           json={"username": "name1", "password": "contraseña-incorrecta"}, timeout=10)
    no_existe = requests.post(f"{BASE}/users/v1/login",
                              json={"username": "usuario-inexistente", "password": "x"}, timeout=10)
    assert existe.json().get("message") == no_existe.json().get("message")


# TODO fase 1: añadid al menos 3 tests funcionales y 2 de seguridad más.
