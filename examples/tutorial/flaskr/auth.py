import functools

from flask import Blueprint
from flask import flash
from flask import g
from flask import redirect
from flask import render_template
from flask import request
from flask import session
from flask import url_for
from werkzeug.security import check_password_hash
from werkzeug.security import generate_password_hash

from .db import get_db

bp = Blueprint("auth", __name__, url_prefix="/auth")


def login_required(view):
    """View decorator that redirects anonymous users to the login page."""

    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for("auth.login"))

        return view(**kwargs)

    return wrapped_view


@bp.before_app_request
def load_logged_in_user():
    """If a user id is stored in the session, load the user object from
    the database into ``g.user``."""
    user_id = session.get("user_id")

    if user_id is None:
        g.user = None
    else:
        g.user = (
            get_db().execute("SELECT * FROM user WHERE id = ?", (user_id,)).fetchone()
        )


@bp.route("/register", methods=("GET", "POST"))
def register():
    """Register a new user.

    Validates that the username is not already taken. Hashes the
    password for security.
    """
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        email = request.form ['email']
        db = get_db()
        error = None

        if not username:
            error = "Se necesita un usuario."
        elif not password:
            error = "Se necesita una contraseña."
        elif not email:
            error = 'Error! es necesario un mail'

        if error is None:
            try:
                db.execute(
                    "INSERT INTO user (username, password,email) VALUES (?, ?, ?)",
                    (username, generate_password_hash(password), email),                 )
                db.commit()
            except db.IntegrityError as e:
                mensaje = e.args[0]
                print(mensaje)
                if "user.username" in mensaje:
                # The username was already taken, which caused the
                # commit to fail. Show a validation error.
                    error = f"Usuario {username} ya esta registrado."
                elif "user.email" in mensaje:
                    error = f"Mail {email} ya esta registrado."
            else:
                # Success, go to the login page.
                return redirect(url_for("auth.login"))

        flash(error)

    return render_template("auth/register.html")


@bp.route("/login", methods=("GET", "POST"))
def login():
    """Log in a registered user by adding the user id to the session."""
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        db = get_db()
        error = None
        user = db.execute(
            "SELECT * FROM user WHERE username = ?", (username,)
        ).fetchone()

        if user is None:
            error = "Usuario o contraseña incorrecta."
        elif not check_password_hash(user["password"], password):
            error = "Usuario o contraseña incorrecta."

        if error is None:
            # store the user id in a new session and return to the index
            session.clear()
            session["user_id"] = user["id"]
            return redirect(url_for("index"))

        flash(error)

    return render_template("auth/login.html")


@bp.route("/logout")
def logout():
    """Clear the current session, including the stored user id."""
    session.clear()
    return redirect(url_for("index"))

@bp.route('/change', methods=('GET','POST'))
def change():
    if request.method == 'POST':
        email = request.form['nuevo_email']
        db= get_db()
        error = None
        if not email:
            error = 'Es necesario un mail.'

        if error is None:
            db.execute(
                'UPDATE user SET email = ? WHERE id = ?', (email, g.user['id'])
            )
            db.commit()
            return redirect(url_for('index'))


    return render_template('auth/change.html')


@bp.route('/delete', methods=('GET','POST'))
def delete_usuario():
    if request.method == 'POST':
        db= get_db()
        error = None

    if error is None:
        db.execute(
            'DELETE user WHERE id = ?', (g.user['id'],)
        )
        db.commit()

        return render_template('auth/change.html')

@bp.before_app_request
def load_logged_in_user():
    user_id = session.get('user_id')