from flaskr.db import get_db

def test_update(client, auth, app):
    auth.login()
    assert client.get("/auth/change").status_code == 200
    response = client.post("/auth/change", data={"nuevo_email": "updated@gmail.com"})
    assert response.status_code == 302
    assert response.headers["Location"] == "/"

    with app.app_context():
        db = get_db()
        post = db.execute("SELECT * FROM user WHERE id = 1").fetchone()
        assert post["email"] == "updated@gmail.com"



def test_delete(client, auth, app):
    auth.login()
    response = client.post("/auth/delete")
    
    assert response.status_code == 302
    assert response.headers["Location"] == "/"

    with app.app_context():
        db = get_db()
        user = db.execute("DELETE FROM user WHERE id = '1'").fetchone()
        assert user is None
