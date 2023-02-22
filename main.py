from flask import Flask, request, jsonify, render_template
from google.cloud import datastore
from google.oauth2 import id_token
from google.auth import jwt
from google.auth.transport import requests
from requests_oauthlib import OAuth2Session
import json
import constants
import os 

app = Flask(__name__)
client = datastore.Client()

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

# Get info to identify a user
oauth = OAuth2Session(constants.CLIENT_ID, redirect_uri=constants.REDIRECT_URI, scope=constants.SCOPE)


# User authorization through redirection
@app.route('/')
def index():
    authorization_url, state = oauth.authorization_url(constants.ENDPOINT, access_type=constants.ACCESS_TYPE, prompt=constants.PROMPT)
    return render_template('welcome.html', authorization_url=authorization_url)


# Get the user's info, add the user to database if it doesn't exist in the database and display User's JWT and unique ID
@app.route('/oauth')
def oauthroute():
    token = oauth.fetch_token(constants.TOKEN_URL, authorization_response=request.url, client_secret=constants.CLIENT_SECRET)
    requests.Request()
    id_info = id_token.verify_oauth2_token(token['id_token'], requests.Request(), constants.CLIENT_ID)

    # Check if this user exists in the database
    query = client.query(kind=constants.users)
    query.add_filter("unique_id", "=", id_info['sub'])
    result = list(query.fetch())
    
    # If the user does not exist, create user account, add the user to database and display user info (JWT and unique ID)
    if len(result) == 0:
        new_user = datastore.entity.Entity(key=client.key(constants.users))
        new_user.update({'unique_id': id_info['sub']})
        client.put(new_user)
        new_user['id'] = new_user.key.id
        return (("<h1>Your account has been created!</h1>\n <p>JWT: %s</p>\n <p>Unique User ID: %s</p>\n" % (token['id_token'], id_info['sub'])), 201)

    # If the user exists in the database, display user info (JWT and unique ID)
    if len(result) == 1:
        return (("<h1>Welcome back!</h1>\n <p>JWT: %s</p>\n <p>Unique User ID: %s</p>\n" % (token['id_token'], id_info['sub'])), 200)


# Get all the users
@app.route('/users', methods=['GET'])
def get_users():
    if request.method == 'GET':
        # Response must allow JSON
        if 'application/json' not in request.accept_mimetypes:
            return (jsonify({"Error": 'Accept-Type not supported'}), 406)

        # Get all users
        query = client.query(kind=constants.users)
        results = list(query.fetch())
        for e in results:
            e["id"] = e.key.id
            e["self"] = request.url + "/" + str(e.key.id)
        output = {"users": results}
        return (jsonify(output), 200)
    else:
        # If the methods are not allowed, return status code 405
        res.headers.set('Allow', "GET")
        return (jsonify(''), 405)


# Create a boat and get all boats of a specific owner
@app.route('/boats', methods=['POST','GET'])
def boats_post_get():
    # Check if JWT is missing. If no, check if JWT is valid.
    jwt_token = request.headers.get('Authorization')
    if jwt_token:
        jwt_token = jwt_token.split(" ")[1]
        try:
            sub = id_token.verify_oauth2_token(jwt_token, requests.Request(), constants.CLIENT_ID)['sub']
        except:
            return(jsonify({"Error": "JWT is invalid"}), 401)
    else:
        return (jsonify({"Error": "JWT is missing"}), 401)
        
    if request.method == 'POST':
        # Response must allow JSON
        if 'application/json' not in request.accept_mimetypes:
            return (jsonify({"Error": "Accept-Type not supported"}), 406)

        # Create a boat
        content = request.get_json()
        if len(content) != 3:
            return (jsonify({"Error": "The request object is missing at least one of the required attributes"}), 400)
        new_boat = datastore.entity.Entity(key=client.key(constants.boats))
        new_boat.update({"name": content["name"], "type": content["type"], "length": content["length"], 'loads': [], "owner": sub})
        client.put(new_boat)
        new_boat['id'] = new_boat.key.id
        new_boat['self'] = request.url + '/' + str(new_boat.key.id)
        return (jsonify(new_boat), 201)
    elif request.method == 'GET':
        # Response must allow JSON
        if 'application/json' not in request.accept_mimetypes:
            return (jsonify({"Error": "Accept-Type not supported"}), 406)

        # Return all boats of this owner with 5 boats at a time
        query = client.query(kind=constants.boats)
        query.add_filter("owner", "=", sub)
        q_limit = int(request.args.get('limit', '5'))
        q_offset = int(request.args.get('offset', '0'))
        l_iterator = query.fetch(limit= q_limit, offset=q_offset)
        pages = l_iterator.pages
        results = list(next(pages))
        if l_iterator.next_page_token:
            next_offset = q_offset + q_limit
            next_url = request.base_url + "?limit=" + str(q_limit) + "&offset=" + str(next_offset)
        else:
            next_url = None
        for e in results:
            e["id"] = e.key.id
            e["self"] = request.url_root + "boats/" + str(e.key.id)
            if len(e['loads']) > 0:
                for load in e['loads']:
                    load['self'] = request.url_root + "loads/" + str(load['id'])
        output = {"boats": results}
        if next_url:
            output["next"] = next_url
        output['total'] = len(list(query.fetch()))
        return (jsonify(output), 200)
    else:
        return jsonify({"Error": "Method not recognized"})


# View, update and delete a boat
@app.route('/boats/<id>', methods=['GET', 'PATCH', 'PUT', 'DELETE'])
def boats_get_patch_put_delete(id):
    # Check if JWT is missing. If no, check if JWT is valid.
    jwt_token = request.headers.get('Authorization')
    if jwt_token:
        jwt_token = jwt_token.split(" ")[1]
        try:
            sub = id_token.verify_oauth2_token(jwt_token, requests.Request(), constants.CLIENT_ID)['sub']
        except:
            return(jsonify({"Error": "JWT is invalid"}), 401)
    else:
        return (jsonify({"Error": "JWT is missing"}), 401)

    # Check if the boat with this id exists
    boat_key = client.key(constants.boats, int(id))
    boat = client.get(key=boat_key)
    if boat == None:
        return (jsonify({"Error": "No boat with this boat_id exists"}), 404)

    # Verify the owner. If yes, then view, update or delete a boat
    if boat['owner'] == sub: 
        if request.method == 'GET':
            # Response must allow JSON
            if 'application/json' not in request.accept_mimetypes:
                return (jsonify({"Error": "Accept-Type not supported"}), 406)

            # Return this boat
            boat["id"] = boat.key.id
            boat["self"] = request.url
            return (jsonify(boat), 200)
        elif request.method == 'PUT':
            # Response must allow JSON
            if 'application/json' not in request.accept_mimetypes:
                return (jsonify({"Error": "Accept-Type not supported"}), 406)

            # Update this boat   
            content = request.get_json()
            if len(content) != 3:
                return (jsonify({"Error": "The request object is missing at least one of the required attributes"}), 400)
            boat.update({"name": content["name"], "type": content["type"], "length": content["length"]})
            boat["id"] = boat.key.id
            boat['self'] = request.url
            client.put(boat)
            return (jsonify(boat), 200)
        elif request.method == 'PATCH':
            # Response must allow JSON
            if 'application/json' not in request.accept_mimetypes:
                return (jsonify({"Error": "Accept-Type not supported"}), 406)

            # Update this boat   
            content = request.get_json()
            if len(content) != 0:
                for key in content:
                    if key == 'name':
                        boat['name'] = content['name']
                    if key == 'type':
                        boat['type'] = content['type']
                    if key == 'length':
                        boat['length'] = content['length']
            else:
                return (jsonify({"Error": "The request object is missing"}), 400)

            boat["id"] = boat.key.id
            boat['self'] = request.url
            client.put(boat)
            return (jsonify(boat), 200)
        elif request.method == 'DELETE':
            # Check if the boat is loaded. If yes, set the carrier of loads to none.
            if len(boat['loads']) > 0:
                for e in boat['loads']:
                    load = client.get(key=client.key(constants.loads, e['id']))
                    load['carrier'] = None
                    client.put(load)
            client.delete(boat_key)
            return (jsonify(''),204)
        else:
            return jsonify({"Error": "Method not recognized"})
    else:
        return (jsonify({"Error": "Sorry you are not the owner"}), 403)


# Create a load and view all loads
@app.route('/loads', methods=['POST','GET'])
def loads_post_get():
    if request.method == 'POST':
        # Response must allow JSON
        if 'application/json' not in request.accept_mimetypes:
            return (jsonify({"Error": "Accept-Type not supported"}), 406)

        # Create a load
        content = request.get_json()
        if len(content) != 3:
            return (jsonify({"Error": "The request object is missing at least one of the required attributes"}), 400)
        new_load = datastore.entity.Entity(key=client.key(constants.loads))
        new_load.update({"volume": content["volume"], 'carrier': None, 'item': content['item'], 'creation_date': content['creation_date']})
        client.put(new_load)
        new_load['id'] = new_load.key.id
        new_load['self'] = request.url + '/' + str(new_load.key.id)
        return (jsonify(new_load), 201)
    elif request.method == 'GET':
        # Response must allow JSON
        if 'application/json' not in request.accept_mimetypes:
            return (jsonify({"Error": "Accept-Type not supported"}), 406)

        # Return all loads with 5 loads at a time
        query = client.query(kind=constants.loads)
        q_limit = int(request.args.get('limit', '5'))
        q_offset = int(request.args.get('offset', '0'))
        g_iterator = query.fetch(limit= q_limit, offset=q_offset)
        pages = g_iterator.pages
        results = list(next(pages))
        if g_iterator.next_page_token:
            next_offset = q_offset + q_limit
            next_url = request.base_url + "?limit=" + str(q_limit) + "&offset=" + str(next_offset)
        else:
            next_url = None
        for e in results:
            e["id"] = e.key.id
            e["self"] = request.url_root + "loads/" + str(e.key.id)
            if e["carrier"] != None:
                e['carrier']['self'] = request.url_root + "boats/" + str(e['carrier']['id'])
        output = {"loads": results}
        if next_url:
            output["next"] = next_url
        output['total'] = len(list(query.fetch()))
        return (jsonify(output), 200)


# View, update and delete a load
@app.route('/loads/<id>', methods=['GET', 'PATCH', 'PUT', 'DELETE'])
def loads_get_patch_put_delete(id):
    if request.method == 'GET':
        # Response must allow JSON
        if 'application/json' not in request.accept_mimetypes:
            return (jsonify({"Error": "Accept-Type not supported"}), 406)

        # Return this load
        load_key = client.key(constants.loads, int(id))
        load = client.get(key=load_key)
        if load == None:
            return (jsonify({"Error": "No load with this load_id exists"}), 404)
        if load["carrier"]:
            load["carrier"]["self"] = request.url_root + "boats/" + str(load["carrier"]["id"])
        load["id"] = load.key.id
        load["self"] = request.url
        return (jsonify(load), 200)
    elif request.method == 'PUT':
        # Response must allow JSON
        if 'application/json' not in request.accept_mimetypes:
            return (jsonify({"Error": "Accept-Type not supported"}), 406)

        # Update this load
        content = request.get_json()
        if len(content) != 3:
            return (jsonify({"Error": "The request object is missing at least one of the required attributes"}), 400)
        load_key = client.key(constants.loads, int(id))
        load = client.get(key=load_key)
        if load == None:
            return (jsonify({"Error": "No load with this load_id exists"}), 404)
        load.update({"volume": content["volume"], 'item': content['item'], 'creation_date': content['creation_date']})
        load["id"] = load.key.id
        load['self'] = request.url
        client.put(load)
        return (jsonify(load), 200)
    elif request.method == 'PATCH':
        # Response must allow JSON
        if 'application/json' not in request.accept_mimetypes:
            return (jsonify({"Error": "Accept-Type not supported"}), 406)

        # Update this load
        content = request.get_json()
        load_key = client.key(constants.loads, int(id))
        load = client.get(key=load_key)
        if load == None:
            return (jsonify({"Error": "No load with this load_id exists"}), 404)
        if len(content) != 0:
            for key in content:
                if key == 'volumn':
                    load['volume'] = content['volume']
                if key == 'item':
                    load['item'] = content['item']
                if key == 'creation_date':
                    load['creation_date'] = content['creation_date']
        else:
            return (jsonify({"Error": "The request object is missing"}), 400)

        load["id"] = load.key.id
        load['self'] = request.url
        client.put(load)
        return (jsonify(load), 200)
    elif request.method == 'DELETE':
        load_key = client.key(constants.loads, int(id))
        load = client.get(key=load_key)
        if load == None:
            return (jsonify({"Error": "No load with this load_id exists"}), 404)
        
        # Check if this load is loaded on a boat. If yes, set the loads of this boat to none.
        if load['carrier'] != None:
            boat = client.get(key=client.key(constants.boats, load['carrier']['id']))
            boat["loads"].remove({'id': load.key.id, "self": request.url_root + "loads/" + str(load.key.id)})
            client.put(boat)
        client.delete(load_key)
        return (jsonify(''),204)
    else:
        return jsonify({"Error": "Method not recognized"})


# Assign a load to a boat and remove a load from a boat
@app.route('/boats/<bid>/loads/<lid>', methods=['PUT','DELETE'])
def add_delete_loads(bid, lid):
    # Check if JWT is missing. If no, check if JWT is valid.
    jwt_token = request.headers.get('Authorization')
    if jwt_token:
        jwt_token = jwt_token.split(" ")[1]
        try:
            sub = id_token.verify_oauth2_token(jwt_token, requests.Request(), constants.CLIENT_ID)['sub']
        except:
            return(jsonify({"Error": "JWT is invalid"}), 401)
    else:
        return (jsonify({"Error": "JWT is missing"}), 401)

    # Check if the boat with this id exists and the load with this id exists
    boat_key = client.key(constants.boats, int(bid))
    boat = client.get(key=boat_key)
    load_key = client.key(constants.loads, int(lid))
    load = client.get(key=load_key)
    if boat == None or load == None:
        return (jsonify({"Error": "The specified boat and/or load does not exist"}), 404)

    # Verify the owner. If yes, then assign a load to a boat or remove a load from a boat
    if boat['owner'] == sub: 
        if request.method == 'PUT':
            if load['carrier'] != None:
                return (jsonify({"Error": "The load is already loaded on a boat"}), 403) 
            boat['loads'].append({"id": load.key.id, "self": request.url_root + "loads/" + str(load.key.id)})
            load['carrier'] = {"id": boat.key.id, "name": boat["name"], "self": request.url_root + 'boats/' + str(boat.key.id)}
            client.put(boat)
            client.put(load)
            return(jsonify(''), 204)
        elif request.method == 'DELETE':
            if load['carrier'] == None:
                return (jsonify({"Error": "No boat with this boat_id is loaded with the load with this load_id"}), 404)
            if load['carrier']['id'] != boat.key.id:
                return (jsonify({"Error": "No boat with this boat_id is loaded with the load with this load_id"}), 404)
            boat['loads'].remove({"id": load.key.id, "self": request.url_root + "loads/" + str(load.key.id)})
            load['carrier'] = None
            client.put(boat)
            client.put(load)
            return(jsonify(''),204)
    else:
        return (jsonify({"Error": "Sorry you are not the owner"}), 403)


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)
    