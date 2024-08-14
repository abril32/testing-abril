from flaskr.db import get_db

def test_update(client, auth, app):
    auth.login()
    assert client.get("/auth/change").status_code == 200
    client.post("/auth/change", data={"nuevo_email": "updated@gmail.com"})

    with app.app_context():
        db = get_db()
        post = db.execute("SELECT * FROM user WHERE id = 1").fetchone()
        assert post["email"] == "updated@gmail.com"