"""Pruebas automatizadas de SecureDev Tickets (se ejecutan en la etapa Test del pipeline)."""
import pytest

from app import create_app


@pytest.fixture
def client(tmp_path):
    app = create_app(tmp_path / "test.db")
    app.config["TESTING"] = True
    return app.test_client()


def login(client, username="ana", password="ana123"):
    return client.post("/login", data={"username": username, "password": password})


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

    