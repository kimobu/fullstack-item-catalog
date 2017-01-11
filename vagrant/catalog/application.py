from __future__ import print_function  # In python 2.7

from flask import Flask, render_template, request, make_response, flash
from flask import redirect, url_for, jsonify
from flask import session as login_session
from functools import wraps

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from db import User, Category, Item

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError

import sys
import random
import string
import httplib2
import json
import requests

app = Flask(__name__)
app.config['DEBUG'] = True


engine = create_engine('sqlite:///catalog.db')
DBSession = sessionmaker(bind=engine)
session = DBSession()

GOOGLE_CLIENT_ID = json.loads(
    open('google_client_secrets.json', 'r').read())['web']['client_id']
FACEBOOK_APP_ACCESS_TOKEN = json.loads(
    open('facebook_client_secrets.json', 'r')
    .read())['web']['app_access_token']


def login_required(f):
    """
    This function checks to see if a user is logged in
    If they are not logged in, they are redirected to the login page
    If they are logged in, they are sent to the page requested
    Other functions will use the @login_required decorator to call this
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not login_session.get('username'):
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function


def render(request, template, **kwargs):
    """
    This is a wrapper function so that every page can be checked for a login
    Additionally, a caller can specify an HTTP status code that will be
    applied to the response object
    """
    code = kwargs.get('code', '200')
    if code:
        return render_template(template, **kwargs), code
    else:
        return render_template(template, **kwargs)


@app.route('/')
def index():
    categories = session.query(Category).all()
    items = session.query(Item).order_by(-Item.id).limit(10)
    return render_template('index.html', categories=categories, items=items)


# Create anti-forgery state token
@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    return render(request, 'login.html', STATE=state)


@app.route('/logout')
def logout():
    if login_session.get('google_id'):
        credentials = json.loads(login_session['credentials'])
        access_token = credentials['access_token']
        if access_token is None:
            response = make_response(
                json.dumps('Current user not connected.'), 401)
            response.headers['Content-Type'] = 'application/json'
            return response
        url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' \
            % access_token
        h = httplib2.Http()
        result = h.request(url, 'GET')[0]
        if result['status'] == '200':
            del login_session['credentials']
            del login_session['google_id']
            del login_session['username']
            del login_session['email']
            del login_session['picture']
            flash('You have been signed out.', 'success')
            return redirect(url_for('index'))
        else:
            flash("You couldn't be logged out. \
                Try again later or clear your cache.", 'error')
            return redirect(url_for('index'))

    elif login_session.get('facebook_id'):
        """ Facebook docs say to just delete your session identifier """
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['facebook_id']
        flash('You have been signed out.', 'success')
        return redirect(url_for('index'))


@app.route('/gconnect', methods=['POST'])
def gconnect():
    if request.args.get('state') != login_session['state']:
        flash('Invalid state parameter', 'error')
        return render(request, 'login.html')
    code = request.data
    try:
        oauth_flow = flow_from_clientsecrets(
            'google_client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        flash('Failed to upgrade the authorization code', 'error')
        return render(request, 'login.html')
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    http_req = httplib2.Http()
    result = json.loads(http_req.request(url, 'GET')[1])
    if result.get('error') is not None:
        flash('%s' % result.get('error'), 'error')
        return render(request, 'login.html')

    google_id = credentials.id_token['sub']
    if result['user_id'] != google_id:
        flash('Token ID doesn\'t match user ID', 'error')
        return render(request, 'login.html')
    if result['issued_to'] != GOOGLE_CLIENT_ID:
        flash('Token ID doesn\t belong to our app', 'error')
        return render(request, 'login.html')
    stored_credentials = login_session.get('credentials')
    stored_google_id = login_session.get('google_id')
    if stored_credentials is not None and google_id == stored_google_id:
        flash('Current user is already connected.', 'message')
        return render(request, 'index.html')
    login_session['credentials'] = credentials.to_json()
    login_session['google_id'] = google_id
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)
    data = answer.json()
    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    user = session.query(User).filter_by(
            username=login_session['username'],
            email=login_session['email'], account_type='google').first()
    if user is None:
        user = User(username=login_session['username'],
                    email=login_session['email'], account_type='google')
        session.add(user)
        session.commit()
    login_session['id'] = user.id
    flash("Successfully logged in with your Google account. Welcome, %s"
          % login_session['username'], 'success')
    return render(request, 'index.html')


@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    if request.args.get('state') != login_session['state']:
        flash('Invalid state parameter', 'error')
        return render(request, 'login.html')
    code = json.loads(request.data)
    fb_app_secret = json.loads(
        open('facebook_client_secrets.json', 'r').read())['web']['app_secret']
    access_token = code['authResponse']['accessToken']
    url = 'https://graph.facebook.com/debug_token?input_token=%s&access_token=%s' % (access_token, FACEBOOK_APP_ACCESS_TOKEN)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    if result['data']['is_valid'] is not True:
        flash("We couldn't validate your login. Please try again", 'error')
        return render(request, 'login.html')
    user_id = result['data']['user_id']
    userinfo_url = "https://graph.facebook.com/v2.8/%s?fields=name,email,id&access_token=%s" % (user_id, access_token)
    h = httplib2.Http()
    result = h.request(userinfo_url, 'GET')[1]
    data = json.loads(result)
    userpicture_url = 'https://graph.facebook.com/v2.8/%s/picture?fields=url&access_token=%s&redirect=false' % (user_id, access_token)
    h = httplib2.Http()
    result = json.loads(h.request(userpicture_url, 'GET')[1])
    picture = result['data']['url']
    login_session['username'] = data['name']
    login_session['facebook_id'] = data['id']
    login_session['email'] = data['email']
    login_session['facebook_id'] = user_id
    login_session['picture'] = picture
    user = session.query(User).filter_by(
            username=login_session['username'],
            email=login_session['email'], account_type='facebook').first()
    if user is None:
        user = User(username=login_session['username'],
                    email=login_session['email'], account_type='facebook')
        session.add(user)
        session.commit()
    login_session['id'] = user.id
    flash("Successfully logged in with your Facebook account. Welcome, %s"
          % login_session['username'], 'success')
    return render(request, 'index.html')


""" Category functions """
@app.route('/category', methods=["GET"])
def list_categories():
    """ This function lists all categories in the database """
    categories = session.query(Category).all()
    return render(request, 'category_list.html', categories=categories)


@app.route('/category/add', methods=["GET", "POST"])
@login_required
def new_category():
    """ This function allows a logged in user to create a new category """
    if request.method == "GET":
        return render(request, 'edit_category.html', category=None)
    elif request.method == "POST":
        name = request.form['name']
        user_id = login_session['id']
        user = session.query(User).get(user_id)
        new_category = Category(name=name, user=user)
        session.add(new_category)
        session.commit()
        return redirect(url_for('list_categories'))


@login_required
@app.route('/category/<int:category_id>', methods=["GET", "POST"])
def edit_category(category_id):
    """ This function allows a logged in user to edit a category that they
        created.
        If the user did not create the category, they are redirected to
        the category_list page
    """
    category = session.query(Category).get(category_id)
    user_id = login_session['id']
    if user_id != category.user_id:
        flash('You are not allowed to edit this category', 'error')
        print ('%s'%category.name, file=sys.stderr)
        return render(request, 'category.html', category=category)
    if request.method == "GET":
        if login_session.get('username'):
            return render(request, 'edit_category.html', category=category)
        else:
            return render(request, 'category.html', category=category)
    elif request.method == "POST":
        name = request.form['name']
        category.name = name
        session.commit()
        flash('Category updated!', 'success')
        return render(request, 'category.html', category=category)


@app.route('/api/category/<int:category_id>', methods=["GET"])
def json_category(category_id):
    """ This function returns a category as a JSON object """
    category = session.query(Category).get(category_id).to_json()
    return jsonify(category)


@login_required
@app.route('/category/delete/<int:category_id>', methods=["GET", "POST"])
def delete_category(category_id):
    """ This function allows a logged in user to delete a category that they
        created.
        If the user did not create the category, they are redirected to
        the category_list page
    """
    category = session.query(Category).get(category_id)
    user_id = login_session['id']
    if user_id != category.user_id:
        categories = session.query(Category).all()
        flash('You are not allowed to delete this category', 'error')
        return render(request, 'category_list.html', categories=categories)
    if request.method == "GET":
        return render(request, 'delete_category.html', category=category)
    else:
        session.delete(category)
        session.commit()
        categories = session.query(Category).all()
        flash('Category deleted', 'success')
        return redirect(url_for('list_categories'))


""" Item functions """
@app.route('/item', methods="GET")
def list_items():
    """ This function lists all items in the database """
    items = session.query(Item).all()
    return render(request, 'item_list.html', items=items)


@login_required
@app.route('/<int:category_id>/item/add', methods=["GET", "POST"])
def new_item(category_id):
    """ This function allows a logged in user to create a new item """
    categories = session.query(Category).all()
    if request.method == "GET":
        return render(request,
                      'edit_item.html', item=None,
                      category_id=category_id, categories=categories)
    elif request.method == "POST":
        name = request.form['name']
        description = request.form['description']
        category_id = request.form['category_id']
        user_id = login_session['id']
        user = session.query(User).get(user_id)
        new_item = Item(name=name, description=description,
                        category_id=category_id, user=user)
        session.add(new_item)
        session.commit()
        flash('Item added', 'success')
        return redirect(url_for('edit_item', item_id=new_item.id))


@login_required
@app.route('/item/<int:item_id>', methods=["GET", "POST"])
def edit_item(item_id):
    """ This function allows a logged in user to edit an item that they
        created.
        If the user did not create the item, they are redirected to
        the item_list page
    """
    item = session.query(Item).get(item_id)
    categories = session.query(Category).all()
    if request.method == "GET":
        if login_session.get('username'):
            return render(request, 'edit_item.html',
                          item=item, categories=categories)
        else:
            return render(request, 'item.html',
                          item=item, categories=categories)
    elif request.method == "POST":
        user_id = login_session['id']
        if user_id != item.user_id:
            categories = session.query(Category).all()
            flash('You are not allowed to edit this item', 'error')
            return render(request, 'edit_item.html',
                          item=item, categories=categories)
        name = request.form['name']
        description = request.form['description']
        category_id = request.form['category_id']
        item.name = name
        item.description = description
        item.category_id = category_id
        session.commit()
        flash('Item updated', 'success')
        return render(request, 'item.html', item=item, categories=categories)


@app.route('/api/item/<int:item_id>', methods=["GET", ])
def json_item(item_id):
    """ This function returns an item as a JSON object """
    item = session.query(Item).get(item_id).to_json()
    return jsonify(item)


@login_required
@app.route('/item/delete/<int:item_id>', methods=["GET", "POST"])
def delete_item(item_id):
    """ This function allows a logged in user to delete an item that they
        created.
        If the user did not create the item, they are redirected to
        the item_list page
    """
    user_id = login_session['id']
    item = session.query(Item).get(item_id)
    if user_id != item.user_id:
        categories = session.query(Category).all()
        flash('You are not allowed to delete this item', 'error')
        return render(request, 'item_list.html',
                      item=item)
    if request.method == "GET":
        item = session.query(Item).get(item_id)
        return render(request, 'delete_item.html', item=item)
    else:
        category_id = item.category_id
        session.delete(item)
        session.commit()
        flash('Item deleted', 'success')
        return redirect(url_for('edit_category', category_id=category_id))

if __name__ == '__main__':
    app.secret_key = 'b9GMTUhIWaP;`q5p'
    app.run(host='0.0.0.0', port=8000)
