import os
from flask import Flask, request, jsonify, abort
from sqlalchemy import exc
import json
from flask_cors import CORS

from .database.models import db_drop_and_create_all, setup_db, Drink
from .auth.auth import AuthError, requires_auth

app = Flask(__name__)
setup_db(app)
CORS(app)

# db_drop_and_create_all()

# ROUTES
'''
    GET /drinks
        it should be a public endpoint
        it should contain only the drink.short() data representation
    returns status code 200 and json {"success": True, "drinks": drinks} where drinks is the list of drinks
        or appropriate status code indicating reason for failure
'''
@app.route("/drinks")
def get_drinks():
    query = Drink.query.all()
    drinks = [d.short() for d in query]
    return jsonify({
        "success": True,
        "drinks": drinks
    }), 200


'''
    GET /drinks-detail
        it should require the 'get:drinks-detail' permission
        it should contain the drink.long() data representation
    returns status code 200 and json {"success": True, "drinks": drinks} where drinks is the list of drinks
        or appropriate status code indicating reason for failure
'''
@app.route("/drinks-detail")
@requires_auth("get:drinks-detail")
def get_drinks_detail(payload):
    query = Drink.query.all()
    drinks = [d.long() for d in query]
    return jsonify({
        "success": True,
        "drinks": drinks
    }), 200


'''
    POST /drinks
        it should create a new row in the drinks table
        it should require the 'post:drinks' permission
        it should contain the drink.long() data representation
    returns status code 200 and json {"success": True, "drinks": drink} where drink an array containing only the newly created drink
        or appropriate status code indicating reason for failure
'''
@app.route("/drinks", methods=["POST"])
@requires_auth("post:drinks")
def add_drinks(payload):
    body = request.get_json()
    drink = Drink()
    drink.recipe = json.dumps(body.get("recipe"))
    drink.title = body.get("title")
    drink.insert()
    return jsonify({
        "success": True,
        "drink": drink.long()
    }), 201

'''
    PATCH /drinks/<id>
        where <id> is the existing model id
        it should respond with a 404 error if <id> is not found
        it should update the corresponding row for <id>
        it should require the 'patch:drinks' permission
        it should contain the drink.long() data representation
    returns status code 200 and json {"success": True, "drinks": drink} where drink an array containing only the updated drink
        or appropriate status code indicating reason for failure
'''
@app.route("/drinks/<int:id>", methods=["PATCH"])
@requires_auth("patch:drinks")
def update_drinks(*args, **kwargs):
    body = request.get_json()
    drink = Drink.query.filter_by(id=kwargs.get("id")).one_or_none()
    if not drink:
        return jsonify({
            "success": True,
            "message": "Drink not found."
        }), 404
    drink.recipe = body.get("recipe", drink.recipe)
    drink.title = body.get("title", drink.title)
    if isinstance(drink.recipe, list):
        drink.recipe = json.dumps(drink.recipe)
    drink.update()
    return jsonify({
        "success": True,
        "drink": drink.long()
    }), 200


'''
    DELETE /drinks/<id>
        where <id> is the existing model id
        it should respond with a 404 error if <id> is not found
        it should delete the corresponding row for <id>
        it should require the 'delete:drinks' permission
    returns status code 200 and json {"success": True, "delete": id} where id is the id of the deleted record
        or appropriate status code indicating reason for failure
'''
@app.route("/drinks/<int:id>", methods=["DELETE"])
@requires_auth("patch:drinks")
def delete_drinks(*args, **kwargs):
    drink = Drink.query.filter_by(id=kwargs.get("id")).one_or_none()
    if not drink:
        return jsonify({
            "success": True,
            "message": "Drink not found."
        }), 404
    drink.delete()
    return jsonify({
        "success": True,
        "delete": kwargs.get("id")
    }), 200

# Error Handling
'''
Example error handling for unprocessable entity
'''
@app.errorhandler(422)
def unprocessable(error):
    return jsonify({
        "success": False,
        "error": 422,
        "message": "unprocessable"
    }), 422


'''
@TODO implement error handlers using the @app.errorhandler(error) decorator
    each error handler should return (with approprate messages):
             jsonify({
                    "success": False, 
                    "error": 404,
                    "message": "resource not found"
                    }), 404

'''

'''
@TODO implement error handler for 404
    error handler should conform to general task above 
'''


'''
@TODO implement error handler for AuthError
    error handler should conform to general task above 
'''
