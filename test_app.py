"""Pruebas automatizadas de SecureDev Tickets (se ejecutan en la etapa Test del pipeline)."""
import re

import pytest

from app import create_app


@pytest.fixture
def client(tmp_path):
    app = create_app(tmp_path / "test.db", secret_key="clave-solo-para-pruebas")
    app.config["TESTING"] = True
    return app.test_client()


def csrf(client, url="/login"):
    """Obtiene el token anti-CSRF del formulario de una página, como lo haría el navegador."""
    html = client.get(url).get_data(as_text=True)
    return re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)


def login(client, username="ana", password="ana123"):
    return client.post(
        "/login", data={"username": username, "password": password, "csrf_token": csrf(client)}
    )


def test_health(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.get_json() == {"status": "ok"}


def test_metrics_expuestas(client):
    client.get("/health")
    response = client.get("/metrics")
    assert response.status_code == 200
    assert b"securedev_http_requests_total" in response.data
    assert b"securedev_login_failures_total" in response.data


def test_rutas_protegidas_redirigen_a_login(client):
    for ruta in ("/", "/search", "/tickets/1"):
        response = client.get(ruta)
        assert response.status_code == 302
        assert "/login" in response.headers["Location"]


def test_login_correcto(client):
    response = login(client)
    assert response.status_code == 302
    assert client.get("/").status_code == 200


def test_login_incorrecto(client):
    response = login(client, password="incorrecta")
    assert response.status_code == 200
    assert "Credenciales inválidas" in response.get_data(as_text=True)

def test_busqueda_no_permite_inyeccion_sql(client):
    login(client)
    payload = "x' UNION SELECT id, username || ':' || password_hash FROM users --"
    response = client.get("/search", query_string={"q": payload})
    html = response.get_data(as_text=True)
    assert response.status_code == 200
    assert "scrypt:" not in html and "pbkdf2:" not in html   # no se filtran hashes
    assert "ana:" not in html

    

# ---------------- Pruebas de regresión de seguridad ----------------

def test_comentario_con_script_se_escapa(client):
    """V-04: un comentario con JavaScript se muestra como texto, no se ejecuta (XSS)."""
    login(client)
    token = csrf(client, "/tickets/1")
    client.post("/tickets/1/comments", data={"body": "<script>alert('xss')</script>", "csrf_token": token})
    html = client.get("/tickets/1").get_data(as_text=True)
    assert "<script>alert('xss')</script>" not in html
    assert "&lt;script&gt;" in html


def test_cabeceras_de_seguridad(client):
    """V-04: las respuestas incluyen CSP y cabeceras anti-clickjacking."""
    response = client.get("/login")
    csp = response.headers["Content-Security-Policy"]
    assert "default-src 'self'" in csp
    assert "unsafe-inline" not in csp
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["X-Content-Type-Options"] == "nosniff"


def test_no_se_puede_ver_ticket_ajeno(client):
    """V-05: ana no puede abrir el ticket 2, que es de bruno (IDOR)."""
    login(client)
    assert client.get("/tickets/1").status_code == 200
    assert client.get("/tickets/2").status_code == 404


def test_no_se_puede_comentar_ticket_ajeno(client):
    """V-05: ana no puede comentar en el ticket de bruno."""
    login(client)
    response = client.post("/tickets/2/comments", data={"body": "intruso", "csrf_token": csrf(client, "/")})
    assert response.status_code == 404


def test_busqueda_solo_muestra_tickets_propios(client):
    """V-05: la búsqueda no revela tickets de otros usuarios."""
    login(client)
    html = client.get("/search", query_string={"q": ""}).get_data(as_text=True)
    assert "Revisión de despliegue" in html      # ticket de ana
    assert "Acceso al panel" not in html          # ticket de bruno


def test_app_no_inicia_sin_secret_key(tmp_path, monkeypatch):
    """V-06: sin SECRET_KEY la app no arranca (no hay clave por defecto)."""
    monkeypatch.delenv("SECRET_KEY", raising=False)
    with pytest.raises(RuntimeError):
        create_app(tmp_path / "x.db")


def test_post_sin_token_csrf_es_rechazado(client):
    """CSRF: un formulario enviado sin el token (p. ej. desde otro sitio) se rechaza."""
    login(client)
    response = client.post("/tickets/1/comments", data={"body": "desde otro sitio"})
    assert response.status_code == 400
    response = client.post("/logout")
    assert response.status_code == 400


def test_login_sin_token_csrf_es_rechazado(client):
    """CSRF: el login también exige token."""
    response = client.post("/login", data={"username": "ana", "password": "ana123"})
    assert response.status_code == 400
