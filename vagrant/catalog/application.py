# !/usr/bin/env python
#
# Catalog Project -
# Store sport equipment information into a database
# and display it using the python flask framework

from flask import Flask, render_template, request
from flask import redirect, url_for, flash, make_response, jsonify
from flask import session as login_session
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Categories, Items, User
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
import requests
import random
import string


app = Flask(__name__)

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Catalog Application"

engine = create_engine('sqlite:///sportsEquipmentwithusers.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


@app.route('/')
def showAllCategories():
    """
        Renders the template that displays the Categories and Latest items
    """
    categories = session.query(Categories).all()
    items = session.query(Items).order_by(Items.date_created.desc()).all()
    return render_template(
                'main_list.html',
                categories=categories,
                items=items
            )


@app.route('/catalog/<string:name>/items')
def showCategoryItems(name):

    """
        Renders the template that displays the Categories and Items
        from the selected Category

        Args:
            name: Name of the selected category
    """

    categories = session.query(Categories).all()
    category = session.query(Categories).filter_by(name=name).one()
    items = session.query(Items).filter_by(categories_id=category.id).all()
    return render_template(
                'items_list.html',
                categories=categories,
                items=items,
                category=category
           )


@app.route('/catalog/<string:name>/<string:item>')
def showItem(name, item):

    """
        Renders the template that displays the information
        of the item

        Args:
            name: Name of the selected category
            item: Name of the selected item
    """

    desc = session.query(Items).filter_by(name=item).one()
    return render_template('item_description.html', item=desc)


@app.route('/catalog/<string:name>/new', methods=['GET', 'POST'])
def createItem(name):

    """
        Displays a form to create a new item

        Args:
            name: Name of the selected category
    """

    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        category = session.query(Categories).filter_by(
                                                id=request.form['category']
                                            ).one()
        newItem = Items(
                name=request.form['title'],
                description=request.form['description'],
                categories_id=category.id,
                categories=category,
                user_id=login_session['user_id']
            )
        session.add(newItem)
        session.commit()
        return redirect(url_for('showAllCategories'))
    else:
        categories = session.query(Categories).all()
        return render_template(
                    'create_item.html',
                    categories=categories,
                    cat=name
                )


@app.route('/catalog/Category/new', methods=['GET', 'POST'])
def createCategory():

    """
        Displays a form to create a new Category
    """

    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        newCategory = Categories(
                        name=request.form['name'],
                        user_id=login_session['user_id']
                    )
        session.add(newCategory)
        session.commit()
        return redirect(url_for('showAllCategories'))
    else:
        categories = session.query(Categories).all()
        return render_template('create_category.html')


@app.route('/catalog/<string:item_name>/edit', methods=['GET', 'POST'])
def editItem(item_name):

    """
        Displays a form to edit an existing item

        Args:
            item_name: Name of the selected item edited
    """

    if 'username' not in login_session:
        return redirect('/login')
    item = session.query(Items).filter_by(name=item_name).one()
    if item.user_id != login_session['user_id']:
        return render_template('unauthorized.html')
    if request.method == 'POST':
        if request.form['title']:
            item.name = request.form['title']
        if request.form['description']:
            item.description = request.form['description']
        if request.form['category']:
            category = session.query(Categories).filter_by(
                                                    id=request.form['category']
                                                ).one()
            item.categories = category
        session.add(item)
        session.commit()
        return redirect(
                    url_for(
                        'showItem',
                        name=item.categories.name,
                        item=item.name
                    )
                )
    else:
        categories = session.query(Categories).all()
        return render_template(
                    'edit_item.html',
                    item=item,
                    categories=categories
                )


@app.route('/catalog/<string:item_name>/delete', methods=['GET', 'POST'])
def deleteItem(item_name):

    """
        Displays a form to delete an item

        Args:
            item_name: Name of the selected item to be deleted
    """

    if 'username' not in login_session:
        return redirect('/login')
    item = session.query(Items).filter_by(name=item_name).one()
    if item.user_id != login_session['user_id']:
        return render_template('unauthorized.html')
    if request.method == 'POST':
        session.delete(item)
        session.commit()
        return redirect(url_for('showAllCategories'))
    else:
        return render_template('delete_item.html', item=item)


@app.route('/login')
def showLogin():

    """
        Renders the login template
    """

    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
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
    url = (
            'https://graph.facebook.com/oauth/access_token?'
            'grant_type=fb_exchange_token&client_id=%s&client'
            '_secret=%s&fb_exchange_token=%s' %
            (app_id, app_secret, access_token)
        )
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]

    # Use token to get user info from API
    userinfo_url = "https://graph.facebook.com/v2.8/me"

    token = result.split(',')[0].split(':')[1].replace('"', '')

    url = (
        'https://graph.facebook.com/v2.8/me?access_token='
        '%s&fields=name,id,email' % token
        )
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    # print "url sent for API access:%s"% url
    # print "API JSON result: %s" % result
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    # The token must be stored in the login_session in order to properly logout
    login_session['access_token'] = token

    # Get user picture
    url = (
            'https://graph.facebook.com/v2.8/me/picture?access_token'
            '=%s&redirect=0&height=200&width=200' % token
        )
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
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px; '
    output += '-webkit-border-radius: 150px;-moz-border-radius: 150px; '
    output += 'text-align:center;"> '

    flash("Now logged in as %s" % login_session['username'])
    return output


@app.route('/fbdisconnect')
def fbdisconnect():

    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    url = (
            'https://graph.facebook.com/%s/permissions?'
            'access_token=%s' % (facebook_id, access_token)
        )
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return "you have been logged out"


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

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(
                        json.dumps('Current user is already connected.'), 200
                    )
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    login_session['provider'] = 'google'

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
    output += ' " style = "width: 300px; height: 300px;border-radius: '
    output += '150px;-webkit-border-radius: 150px;-moz-border-radius: '
    output += '150px;text-align:center;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output


@app.route('/gdisconnect')
def gdisconnect():
    access_token = login_session.get('access_token')
    if access_token is None:
        print 'Access Token is None'
        response = make_response(
                        json.dumps('Current user not connected.'), 401
                    )
        response.headers['Content-Type'] = 'application/json'
        return response
    print 'In gdisconnect access token is %s', access_token
    print 'User name is: '
    print login_session['username']
    url = (
        'https://accounts.google.com/o/oauth2/revoke?token=%s' %
        login_session['access_token']
    )
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    print 'result is '
    print result
    if result['status'] == '200':
        del login_session['access_token']
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return redirect(url_for('showAllCategories'))
    else:
        response = make_response(
                        json.dumps(
                            'Failed to revoke token for given user.',
                            400
                        )
                    )
        response.headers['Content-Type'] = 'application/json'
        return response


def createUser(login_session):

    """
        Creates a new user and stores them in the database

        Args:
            login_session:  Contains the users login information
    """

    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):

    """
        Retrieves the user information

        Args:
            user_id:  The users id number
    """

    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):

    """
        Retrieves the user id

        Args:
            email:  The users email
    """

    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


@app.route('/disconnect')
def disconnect():

    """
        Remove all login information from computer
    """

    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            del login_session['gplus_id']
        if login_session['provider'] == 'facebook':
            fbdisconnect()
            del login_session['facebook_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        del login_session['provider']
        flash("You have successfully been logged out.")
        return redirect(url_for('showAllCategories'))
    else:
        flash("You were not logged in")
        return redirect(url_for('showAllCategories'))


@app.route('/catalog.json')
def catalogJSON():

    """
        Displays the catalog information in JSON form
    """

    categories = session.query(Categories).all()

    catalogList = []
    for c in categories:

        catalogDict = {
            'Id': c.id,
            'Name': c.name,
        }

        items = session.query(Items).filter_by(categories_id=c.id).all()
        catalogDict['Items'] = []
        for i in items:
            item = {
                'Id': i.id,
                'Name': i.name,
                'Descripion': i.description
            }
            catalogDict['Items'].append(item)

        catalogList.append(catalogDict)

    return jsonify(Catalog=catalogList)


if __name__ == '__main__':
    app.secret_key = 'super secret'
    app.debug = True
    app.run(host='0.0.0.0', port=8000)
    login_manager = LoginManager()
    login_manager.init_app(app)
