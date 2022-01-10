from todo import app, db
from flask import request, jsonify
from flask.helpers import make_response
from functools import wraps
from todo.models import User, ToDo
from werkzeug.security import generate_password_hash, check_password_hash
import uuid 
import jwt
import datetime


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token=None

        if "x-access-token" in request.headers:
            token=request.headers["x-access-token"]
        
        if not token:
            return jsonify({"message":"Authentication token is missing"}), 401

        try:
            data=jwt.decode(token, app.config["SECRET_KEY"], algorithms="HS256")
            current_user=User.query.filter_by(public_id=data["public_id"]).first()
        except Exception as e:
            return jsonify({"message":"Token is invalid "+str(e)}), 403

        return f(current_user, *args, **kwargs)
    
    return decorated

@app.route("/test")
def hello_world():
    return "Hi Hello World!!"

@app.route('/user', methods=["GET"])
@token_required
def get_all_users(current_user):
    
    if not current_user.admin:
        return jsonify({"message":"cannot perform this function!"})

    users=User.query.all()

    output=[]

    for user in users:
        user_data={}
        user_data["public_id"]=user.public_id
        user_data["name"]=user.name
        user_data["password"]=user.password
        user_data["admin"]=user.admin

        output.append(user_data)

    return jsonify({"users": output})

@app.route('/user/<public_id>', methods=["GET"])
@token_required
def get_one_user(current_user, public_id):
    user=User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({"message":"No user found!"})
    
    user_data={}
    user_data["public_id"]=user.public_id
    user_data["name"]=user.name
    user_data["password"]=user.password
    user_data["admin"]=user.admin

    return jsonify({"user": user_data})

@app.route('/user', methods=["POST"])
@token_required
def create_user(current_user):
    if not current_user.admin:
        return jsonify({"message":"cannot perform this function!"})
     
    data=request.get_json()
    hashed_pwd=generate_password_hash(data["password"],method="sha256")
    suuid=str(uuid.uuid4())
    print(suuid)
    new_user=User(public_id=suuid, name=data["name"], password=hashed_pwd, admin=False)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message":"New user created successfully!"})

@app.route('/user/<public_id>', methods=["PUT"])
@token_required
def promote_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({"message":"cannot perform this function!"})
     
    user=User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({"message":"No user found!"})
    
    user.admin=True
    db.session.commit()

    return jsonify({"message":"User has been promoted!"})

@app.route('/user/<public_id>', methods=["DELETE"])
@token_required
def delete_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({"message":"cannot perform this function!"})
     
    user=User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({"message":"No user found!"})
    
    db.session.delete(user)
    db.session.commit()

    return jsonify({"message":"User has been deleted!"})

@app.route("/login")
def login():
    auth=request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response("Authentication is required.",401, {"WWW-Authenticate":"Basic realm ='Login required!'"})

    user=User.query.filter_by(name=auth.username).first()

    if not user:
        return make_response("Could not find user",401, {"WWW-Authenticate":"Basic realm ='Login required!'"})
    
    if check_password_hash(user.password, auth.password):
        token = jwt.encode({"public_id":user.public_id, "exp":datetime.datetime.utcnow()+datetime.timedelta(minutes=30)}, app.config["SECRET_KEY"], algorithm="HS256")
        return jsonify({"token":token})
    
    return make_response("Password do not match",401, {"WWW-Authenticate":"Basic realm ='Login required!'"})

@app.route("/todo", methods=["GET"])
@token_required
def get_all_todos(current_user):
    todos=ToDo.query.filter_by(user_id=current_user.id).all()

    output=[]

    for todo in todos:
        todo_data={}
        todo_data["id"]=todo.id
        todo_data["text"]=todo.text
        todo_data["complete"]=todo.complete
        output.append(todo_data)

    return jsonify({"todos": output})

@app.route("/todo/<todo_id>", methods=["GET"])
@token_required
def get_one_todo(current_user, todo_id):
    todo = ToDo.query.filter_by(user_id=current_user.id, id=todo_id).first()

    if not todo:
        return jsonify({"message":"Could not find specified todo!"})
    
    todo_data={}
    todo_data["id"]=todo.id
    todo_data["text"]=todo.text
    todo_data["complete"]=todo.complete

    return {"todo":todo_data}

@app.route("/todo", methods=["POST"])
@token_required
def create_todo(current_user):
    data = request.get_json();
    new_todo = ToDo(text=data["text"], complete=False, user_id=current_user.id)

    db.session.add(new_todo)
    db.session.commit()

    return jsonify({"message":"ToDo created!"})

@app.route("/todo/<todo_id>", methods=["PUT"])
@token_required
def complete_todo(current_user, todo_id):
    todo = ToDo.query.filter_by(user_id=current_user.id, id=todo_id).first()

    if not todo:
        return jsonify({"message":"Could not find specified todo!"})
    
    return jsonify({"message":"ToDo completed!"})

@app.route("/todo/<todo_id>", methods=["DELETE"])
@token_required
def delete_todo(current_user, todo_id):
    todo = ToDo.query.filter_by(user_id=current_user.id, id=todo_id).first()

    if not todo:
        return jsonify({"message":"Could not find specified todo!"})

    db.session.delete(todo)
    db.session.commit()    
    return jsonify({"message":"ToDo item deleted!"})