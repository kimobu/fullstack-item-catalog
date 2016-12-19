from __future__ import print_function  # In python 2.7

from flask import Flask, render_template, request, make_response, flash
from flask import session as login_session


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
    open('facebook_client_secrets.json', 'r').read())['web']['app_access_token']

def render(request, template, **kwargs):
    """
    This is a wrapper function so that every page can be checked for a login
    Additionally, a caller can specify an HTTP status code that will be
    applied to the response object
    """
    username = request.cookies.get('name')
    logged_in = False
    code = kwargs.get('code', '200')
    if code:
        return render_template(template, logged_in=logged_in, **kwargs), code
    else:
        return render_template(template, logged_in=logged_in, **kwargs)


@app.route('/')
def index():
    categories = session.query(Category).all()
    return render_template('index.html', categories=categories)


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
            response = make_response(json.dumps('Current user not connected.'), 401)
            response.headers['Content-Type'] = 'application/json'
            return response
        url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
        h = httplib2.Http()
        result = h.request(url, 'GET')[0]
        if result['status'] == '200':
            del login_session['credentials']
            del login_session['google_id']
            del login_session['username']
            del login_session['email']
            del login_session['picture']
            flash('You have been signed out.', 'success')
            return render(request, 'index.html')
        else:
            flash("You couldn't be logged out. \
                Try again later or clear your cache.", 'error')
            return render(request, 'index.html')

    elif login_session.get('facebook_id'):
        """ Facebook docs say to just delete your session identifier """
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['facebook_id']
        flash('You have been signed out.', 'success')
        return render(request, 'index.html')


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
    userpicture_url = "https://graph.facebook.com/v2.8/%s/picture?fields=url&access_token=%s&redirect=false" % (user_id, access_token)
    h = httplib2.Http()
    result = json.loads(h.request(userpicture_url, 'GET')[1])
    picture = result['data']['url']
    login_session['username'] = data['name']
    login_session['facebook_id'] = data['id']
    login_session['email'] = data['email']
    login_session['facebook_id'] = user_id
    login_session['picture'] = picture

    flash("Successfully logged in with your Facebook account. Welcome, %s"
          % login_session['username'], 'success')
    return render(request, 'index.html')


if __name__ == '__main__':
    app.secret_key = 'b9GMTUhIWaP;`q5p'
    app.run(host='0.0.0.0', port=8000)
