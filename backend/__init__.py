from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, json, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt

app = Flask(__name__)

app.config['SECRET_KEY'] = 'thisissecret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database/todo.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

from backend.classes.user import User
from backend.classes.todo import ToDo

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message' : 'Token is missing!'}), 401

        try: 
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms="HS256")
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message': 'Invalid Token'}), 401
        
        return f(current_user, *args, **kwargs)

    return decorated
        
@app.route('/user', methods=['GET'])
@token_required
def get_all_users(current_user):

    if not current_user.admin:
        return jsonify({'message':'admin function only!'})

    users = User.query.all()

    output = []

    for user in users:
        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['name'] = user.name
        user_data['password'] = user.password
        user_data['admin'] = user.admin
        output.append(user_data)

    return jsonify({'users': output})

@app.route('/user/<public_id>', methods=['GET'])
@token_required
def get_one_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({'message':'admin function only!'})
        
    user = User.query.filter_by(public_id = public_id).first()

    if not user:
        return jsonify({"message" : "no user found"})
 
    user_data = {}
    user_data['public_id'] = user.public_id
    user_data['name'] = user.name
    user_data['password'] = user.password
    user_data['admin'] = user.admin
    
    return jsonify({'user': user_data})

@app.route('/user', methods=['POST'])
@token_required
def create_user(current_user):
    if not current_user.admin:
        return jsonify({'message':'admin function only!'})
        
    data = request.get_json()

    hash_password = generate_password_hash(data['password'], method='sha256')

    new_user = User(public_id=str(uuid.uuid4()), 
                    name=data['name'], 
                    password=hash_password, 
                    admin=False)
                    
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'new user created'})

@app.route('/user/<public_id>', methods=['PUT'])
@token_required
def promote_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({'message':'admin function only!'})
        
    user = User.query.filter_by(public_id = public_id).first()

    if not user:
        return jsonify({"message" : "no user found"})

    user.admin = True
    db.session.commit()

    return jsonify({"message": "User has been promoted!"})

@app.route('/user/<public_id>', methods=['DELETE'])
@token_required
def delete_user(current_user, public_id):
    user = User.query.filter_by(public_id = public_id).first()

    if not current_user.admin:
        return jsonify({'message':'admin function only!'})
        
    if not user:
        return jsonify({"message" : "no user found"})

    db.session.delete(user)
    db.session.commit()

    return jsonify({"message": "User has been deleted!"})

@app.route('/login')
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify user', 401, {'WWW-Authenticate': 'Basic realm="Login Required!"'})
    
    user = User.query.filter_by(name=auth.username).first()

    if not user:
        # return jsonify({'message':'not a valid user'})
        return make_response('Could not verify user', 401, {'WWW-Authenticate': 'Basic realm="Login Required!"'})

    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'public_id': user.public_id, 
                            'exp': datetime.utcnow() + timedelta(minutes=30)}
                            , app.config['SECRET_KEY'])
        # return jsonify({'token' : token.decode('UTF-8')})
        return jsonify({'token' : token})

    else:
        return make_response('Could not verify user', 401, {'WWW-Authenticate': 'Basic realm="Login Required!"'})

@app.route('/todo', methods=['GET'])
@token_required
def get_all_todos(current_user):
    todos = ToDo.query.filter_by(user_id=current_user.id)

    output = []
    for todo in todos:
        todo_data = {}
        todo_data['id'] = todo.id
        todo_data['text'] = todo.text
        todo_data['complete'] = todo.complete
        output.append(todo_data)

    return jsonify({'todos': output})

@app.route('/todo/<todo_id>', methods=['GET'])
@token_required
def get_one_todo(current_user, todo_id):

    todo = ToDo.query.filter_by(user_id=current_user.id, id=todo_id).first()

    if not todo:
        return jsonify({'message':'To Do item not found!'})
    
    todo_data = {}
    todo_data['id'] = todo.id
    todo_data['text'] = todo.text
    todo_data['complete'] = todo.complete

    return jsonify({'todo': todo_data})

@app.route('/todo', methods=['POST'])
@token_required
def create_todo(current_user):
    data = request.get_json()

    new_todo = ToDo(text=data['text'], complete=False, user_id=current_user.id)
    db.session.add(new_todo)
    db.session.commit()

    return jsonify({'message':'todo created'})

@app.route('/todo/<todo_id>', methods=['PUT'])
@token_required
def toggle_todo_complete(current_user, todo_id):
    todo = ToDo.query.filter_by(user_id=current_user.id, id=todo_id).first()

    if not todo:
        return jsonify({'message':'To Do item not found!'})
    
    todo.complete = not todo.complete
    db.session.commit()
    return jsonify({'message': 'To Do toggled'})

@app.route('/todo/<todo_id>', methods=['DELETE'])
@token_required
def delete_todo(current_user, todo_id):
    todo = ToDo.query.filter_by(user_id=current_user.id, id=todo_id).first()

    if not todo:
        return jsonify({'message':'To Do item not found!'})
    
    db.session.delete(todo)
    db.session.commit()
    return jsonify({'message':'To Do deleted'})

if __name__ == '__main__':
    pass