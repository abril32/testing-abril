import pytest
from flask import g
from flask import session

from flaskr.db import get_db


def test_register(client, app):
    # test that viewing the page renders without template errors
    assert client.get("/auth/register").status_code == 200

    # test that successful registration redirects to the login page
    response = client.post("/auth/register", data={"username": "a","email": "mxil", "password": "a"})
    assert response.headers["Location"] == "/auth/login"

    # test that the user was inserted into the database
    with app.app_context():
        assert (
            get_db().execute("SELECT * FROM user WHERE username = 'a'").fetchone()
            is not None
        )


@pytest.mark.parametrize(
    ("username", "email","password", "message"),
    (
        ("", "a", "a", "Se necesita un usuario."),
        ("a", "", "a", "Error! es necesario un mail"),
        ("a", "a", "", "Se necesita una contraseña."),
        ("test", "mail", "test", "ya esta registrado."),
    ),
)
def test_register_validate_input(client, username, email, password, message):
    response = client.post(
        "/auth/register", data={"username": username, "password": password, "email":email}
    )
    assert message in response.data.decode()


def test_login(client, auth):
    # test that viewing the page renders without template errors
    assert client.get("/auth/login").status_code == 200

    # test that successful login redirects to the index page
    response = auth.login()
    assert response.headers["Location"] == "/"

    # login request set the user_id in the session
    # check that the user is loaded from the session
    with client:
        client.get("/")
        assert session["user_id"] == 1
        assert g.user["username"] == "test"


@pytest.mark.parametrize(
    ("username", "password", "message"),
    (("a", "test", "Usuario o contraseña incorrecta."), 
     ("test", "a", "Usuario o contraseña incorrecta.")),
)
def test_login_validate_input(auth, username, password, message):
    response = auth.login(username, password)
    assert message in response.data.decode()


def test_logout(client, auth):
    auth.login()

    with client:
        auth.logout()
        assert "user_id" not in session
