from flask import Blueprint, render_template

auth = Blueprint('auth', __name__)


@auth.route('/')
def login():
    return "<p>Login</p>"
