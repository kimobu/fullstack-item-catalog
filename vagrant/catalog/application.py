from __future__ import print_function  # In python 2.7

from flask import Flask, render_template, request

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from db import User, Category, Item

import sys


app = Flask(__name__)
app.config['DEBUG'] = True


engine = create_engine('sqlite:///catalog.db')
DBSession = sessionmaker(bind=engine)
session = DBSession()


def render(request, template, **kwargs):
    """
    This is a wrapper function so that every page can be checked for a login
    Additionally, a caller can specify an HTTP status code that will be
    applied to the response object
    """
    username = request.cookies.get('name')
    logged_in = check_secure_val(username)
    code = kwargs.get('code', '200')
    if code:
        return render_template(template, logged_in=logged_in, **kwargs), code
    else:
        return render_template(template, logged_in=logged_in, **kwargs)


@app.route('/')
def index():
    categories = session.query(Category).all()
    return render_template('index.html', categories=categories)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)
