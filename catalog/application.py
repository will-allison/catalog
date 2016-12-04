from flask import Flask, render_template, request
from flask import redirect, url_for, flash, jsonify
from sqlalchemy import create_engine, desc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, User, Category, CategoryItem
from flask import session as login_session
import random
import string
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests


app = Flask(__name__)
CLIENT_ID = json.loads(
   open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Catalog Application"
engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()


# API
@app.route('/catalog/JSON')
def catalogJOSN():
    categories = session.query(Category)
    return jsonify(Category=[i.serialize for i in categories])


@app.route('/catalog/<string:category_name>/JSON')
def categoryItemJSON(category_name):
    category = session.query(Category).filter_by(name=category_name).one()
    items = session.query(CategoryItem).filter_by(
        category_id=category.id).all()
    return jsonify(CategoryItem=[i.serialize for i in items])


@app.route('/catalog/<string:category_name>/<string:item_title>/JSON')
def itemJSON(category_name, item_title):
    category = session.query(Category).filter_by(name=category_name).one()
    item = session.query(CategoryItem).filter_by(
        category_id=category.id).filter_by(title=item_title).one()
    return jsonify(CategoryItem=item.serialize)


# Create anti-forgery state token
@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    # return "The current session state is %s" % login_session['state']
    return render_template('login.html', STATE=state)


@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data
    print "access token received %s " % access_token

    app_id = json.loads(open('fb_client_secrets.json', 'r').read())[
        'web']['app_id']
    app_secret = json.loads(
        open('fb_client_secrets.json', 'r').read())['web']['app_secret']
    url = """https://graph.facebook.com/oauth/access_token?grant_type=
        fb_exchange_token&client_id=%s&client_secret=%s
        &fb_exchange_token=%s""" % (
        app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]

    # Use token to get user info from API
    userinfo_url = "https://graph.facebook.com/v2.4/me"
    # strip expire tag from access token
    token = result.split("&")[0]
    url = 'https://graph.facebook.com/v2.4/me?%s&fields=name,id,email' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    print "url sent for API access:%s" % url
    print "API JSON result: %s" % result
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data['name']
    login_session['email'] = data['email']
    login_session['facebook_id'] = data['id']

    # The token must be stored in the login_session
    # in order to properly logout, let's strip out the
    # information before the equals sign in our token
    stored_token = token.split("=")[1]
    login_session['access_token'] = stored_token

    # Get user picture
    url = """https://graph.facebook.com/v2.4/me/picture?
        %s&redirect=0&height=200&width=200' % token"""
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['picture'] = data["data"]["url"]

    # see if user exists
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']

    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += """ ' style = "width: 300px; height: 300px;
                border-radius: 150px;
                -webkit-border-radius: 150px;-moz-border-radius: 150px;' """

    flash("Now logged in as %s" % login_session['username'])
    return output


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data
    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    print access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_credentials = login_session.get('credentials')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        response = make_response(
            json.dumps('Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['credentials'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()
    login_session['provider'] = 'google'
    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    # See if user exists, create if false
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)

    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += """ ' style = "width: 300px; height: 300px;
        border-radius: 150px;-webkit-border-radius: 150px;
        -moz-border-radius: 150px;'> """
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output


@app.route('/gdisconnect')
def gdisconnect():
    access_token = login_session['credentials']
    print 'In gdisconnect access token is %s', access_token
    print 'User name is: '
    print login_session['username']
    if access_token is None:
        print 'Access Token is None'
        response = make_response(json.dumps('Current user not connected.'),
                                401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = """https://accounts.google.com/
        o/oauth2/revoke?token=%s""" % login_session['credentials']
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    print 'result is '
    print result
    if result['status'] == '200':
        del login_session['credentials']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:

        response = make_response(json.dumps(
            'Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


# User Helper Functions
def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


@app.route('/')
@app.route('/catalog')
def showCatalog():
    categories = session.query(Category)
    # latest items goes gere
    items = session.query(CategoryItem).order_by(
        desc(CategoryItem.created_time)).limit(10)
    return render_template('catalog.html', categories=categories, items=items)


@app.route('/catalog/new', methods=['GET', 'POST'])
def newCategory():
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        category_name = request.form['name']
        existingCategory = session.query(Category).filter_by(
            name=category_name).all()
        if existingCategory:
            flash("A Category with this name already exists")
            return redirect(url_for('newCategory'))
        else:
            newCategory = Category(
                name=category_name, user_id=login_session['user_id'])
            session.add(newCategory)
            flash('New Category %s Successfully Created' % newCategory.name)
            session.commit()
            return redirect(url_for('showCatalog'))
    else:
        return render_template('newCategory.html')


@app.route('/catalog/<string:category_name>')
def showCategory(category_name):
    category = session.query(Category).filter_by(name=category_name).one()
    items = session.query(CategoryItem).filter_by(category_id=category.id)
    categories = session.query(Category)
    # creator = getUserInfo(restaurant.user_id)
    return render_template(
        "category.html", category=category, items=items, categories=categories)


@app.route('/catalog/item/new', methods=['GET', 'POST'])
def newItem():
    if 'username' not in login_session:
        return redirect('/login')
    categories = session.query(Category)
    if request.method == 'POST':
        category_id = request.form['category_id']
        newItem_title = request.form['title']
        newItem = CategoryItem(title=newItem_title, description=request.form['description'], category_id=category_id, user_id=login_session['user_id'])
        existingItem = session.query(CategoryItem).filter_by(category_id=category_id).filter_by(
            title=newItem_title).all()
        if existingItem:
            flash("An Item with this name already exists")
            return redirect(url_for('newItem'))
        print newItem.category_id
        session.add(newItem)
        flash('New Item %s Successfully Created' % newItem.title)
        session.commit()
        selectedCategory = session.query(
            Category).filter_by(id=category_id).one()
        print "Category Name:"
        print selectedCategory.name
        return redirect('/catalog/%s' % selectedCategory.name)
    else:
        return render_template('newitem.html', categories=categories)


@app.route("""/catalog/<string:category_name>
    /<string:item_title>/edit""", methods=['GET', 'POST'])
def editItem(category_name, item_title):
    if 'username' not in login_session:
        return redirect('/login')
    categories = session.query(Category)
    category = session.query(Category).filter_by(name=category_name).one()
    itemToEdit = session.query(CategoryItem).filter_by(
        title=item_title, category_id=category.id).one()
    if itemToEdit.user_id != login_session['user_id']:
        return """<script>function myFunction()
        {alert('You are not authorized to edit
        this restaurant. Please create your own
        restaurant in order to edit.');}
        </script><body onload='myFunction()''>"""
    if request.method == 'POST':
        itemToEdit.category_id = request.form['category_id']
        itemToEdit.title = request.form['title']
        itemToEdit.description = request.form['description']
        newCategory = session.query(Category).filter_by(
            id=itemToEdit.category_id).one()
        session.add(itemToEdit)
        flash('Item %s Successfully Edited' % itemToEdit.title)
        session.commit()
        return redirect('/catalog/%s/%s' % (
            newCategory.name, itemToEdit.title))
    else:
        return render_template('edititem.html', item_title=itemToEdit.title,
            description=itemToEdit.description, categories=categories,
            category_name=category_name)


@app.route('/catalog/<string:category_name>/<string:item_title>/delete', methods=['GET', 'POST'])
def deleteItem(category_name, item_title):
    if 'username' not in login_session:
        return redirect('/login')
    category = session.query(Category).filter_by(name=category_name).one()
    itemToDelete = session.query(CategoryItem).filter_by(
        title=item_title, category_id=category.id).one()
    if itemToDelete.user_id != login_session['user_id']:
        return """<script>function myFunction() {alert('You are not authorized to edit
        this restaurant. Please create your own
        restaurant in order to edit.');}
        </script><body onload='myFunction()''>"""
    if request.method == 'POST':
        session.delete(itemToDelete)
        session.commit()
        flash("Item deleted!")
        return redirect('/catalog/%s' % category_name)
    else:
        return render_template(
            'deleteitem.html', item_title=itemToDelete.title,
            category_name=category_name)


@app.route('/catalog/<string:category_name>/<string:item_title>')
def showItem(category_name, item_title):
    if login_session:
        currentUser = login_session['user_id']
    category = session.query(Category).filter_by(name=category_name).one()
    item = session.query(CategoryItem).filter_by(
        title=item_title, category_id=category.id).one()
    print "user_id %s" % item.user_id
    return render_template("item.html", item=item, category=category,
        currentUser=currentUser)


@app.route('/flush')
def flush():
    return Session.rollback()


# Disconnect based on provider
@app.route('/disconnect')
def disconnect():
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            # del login_session['gplus_id']
            # del login_session['credentials']
        if login_session['provider'] == 'facebook':
            fbdisconnect()
            del login_session['facebook_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        del login_session['provider']
        flash("You have successfully been logged out.")
        return redirect(url_for('showCatalog'))
    else:
        flash("You were not logged in")
        return redirect(url_for('showCatalog'))

if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=8000)
