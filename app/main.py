

from flask import Flask, request, jsonify
from flask_cors import CORS
import redis
import json
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps

r = redis.Redis(host='redis', port=6379, db=0, decode_responses=True)
app = Flask(__name__)
CORS(app)
r = redis.Redis(host='redis', port=6379, db=0, decode_responses=True)

# Secret key for JWT (in production, use env var)
app.config['SECRET_KEY'] = 'supersecretkey'

# Helper: token required decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(" ")[-1]
        if not token:
            return jsonify({'error': 'Token is missing!'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = r.get(f"user:{data['username']}")
            if not current_user:
                return jsonify({'error': 'User not found!'}), 401
            current_user = json.loads(current_user)
        except Exception as e:
            return jsonify({'error': 'Token is invalid!'}), 401
        return f(current_user, *args, **kwargs)
    return decorated

# User registration
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    if r.exists(f"user:{username}"):
        return jsonify({'error': 'User already exists'}), 400
    hashed_pw = generate_password_hash(password)
    user = {'username': username, 'password': hashed_pw}
    r.set(f"user:{username}", json.dumps(user))
    return jsonify({'message': 'User registered successfully'}), 201

# User login
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    user_data = r.get(f"user:{username}")
    if not user_data:
        return jsonify({'error': 'Invalid username or password'}), 401
    user = json.loads(user_data)
    if not check_password_hash(user['password'], password):
        return jsonify({'error': 'Invalid username or password'}), 401
    token = jwt.encode({
        'username': username,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
    }, app.config['SECRET_KEY'], algorithm="HS256")
    return jsonify({'token': token}), 200

@app.route('/recipes', methods=['GET'])
@token_required
def list_recipes(current_user):
    username = current_user['username']
    user_recipes_key = f"user:{username}:recipes"
    recipes = []
    recipe_ids = r.smembers(user_recipes_key)
    for recipe_id in recipe_ids:
        recipe_data = r.get(f"user:{username}:recipe:{recipe_id}")
        if recipe_data:
            recipes.append(json.loads(recipe_data))
    return jsonify(recipes), 200

@app.route('/recipes', methods=['POST'])
@token_required
def create_recipe(current_user):
    username = current_user['username']
    data = request.json
    recipe_id = data.get('id')
    if not recipe_id:
        return jsonify({'error': 'Recipe ID required'}), 400
    user_recipes_key = f"user:{username}:recipes"
    recipe_key = f"user:{username}:recipe:{recipe_id}"
    if r.sismember(user_recipes_key, recipe_id):
        return jsonify({'error': 'Recipe ID already exists for this user'}), 400
    r.sadd(user_recipes_key, recipe_id)
    r.set(recipe_key, json.dumps(data))
    return jsonify({'message': 'Recipe created', 'id': recipe_id}), 201

@app.route('/recipes/<recipe_id>', methods=['GET'])
@token_required
def get_recipe(current_user, recipe_id):
    username = current_user['username']
    recipe_key = f"user:{username}:recipe:{recipe_id}"
    recipe = r.get(recipe_key)
    if not recipe:
        return jsonify({'error': 'Recipe not found'}), 404
    return jsonify(json.loads(recipe)), 200

@app.route('/recipes/<recipe_id>', methods=['PUT'])
@token_required
def update_recipe(current_user, recipe_id):
    username = current_user['username']
    data = request.json
    recipe_key = f"user:{username}:recipe:{recipe_id}"
    user_recipes_key = f"user:{username}:recipes"
    if not r.sismember(user_recipes_key, recipe_id):
        return jsonify({'error': 'Recipe not found'}), 404
    r.set(recipe_key, json.dumps(data))
    return jsonify({'message': 'Recipe updated'}), 200

@app.route('/recipes/<recipe_id>', methods=['DELETE'])
@token_required
def delete_recipe(current_user, recipe_id):
    username = current_user['username']
    recipe_key = f"user:{username}:recipe:{recipe_id}"
    user_recipes_key = f"user:{username}:recipes"
    if not r.sismember(user_recipes_key, recipe_id):
        return jsonify({'error': 'Recipe not found'}), 404
    r.delete(recipe_key)
    r.srem(user_recipes_key, recipe_id)
    return jsonify({'message': 'Recipe deleted'}), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
