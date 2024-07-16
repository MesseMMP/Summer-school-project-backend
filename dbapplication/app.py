from flask import request, jsonify

from config import app, db
from models import User, Joke, Like
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from datetime import datetime


@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    is_admin = data.get('isAdmin', False)
    admin_secret = data.get('adminSecret', '')

    if User.query.filter_by(username=username).first() or User.query.filter_by(email=email).first():
        return jsonify({'message': 'User with same nickname or email already exists!'}), 400

    if is_admin and admin_secret != app.config['ADMIN_SECRET']:
        return jsonify({'message': 'Invalid admin secret!'}), 403

    user = User(username=username, email=email, is_admin=is_admin)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()

    return jsonify({'message': 'Registration successful!'}), 201


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    user = User.query.filter_by(username=username).first()

    if user and user.check_password(password):
        access_token = create_access_token(identity=user.id)
        return jsonify({'access_token': access_token}), 200

    return jsonify({'message': 'Invalid credentials!'}), 401


@app.route('/create-joke', methods=['POST'])
@jwt_required()
def create_joke():
    data = request.get_json()
    title = data.get('title')
    text = data.get('text')
    tags = data.get('tags')
    user_id = get_jwt_identity()
    joke = Joke(title=title, text=text, tags=tags, pub_date=str(datetime.utcnow()), user_id=user_id)
    db.session.add(joke)
    db.session.commit()

    return jsonify({'message': 'Joke created successfully!'}), 201


@app.route('/jokes', methods=['GET'])
def get_jokes():
    def find_likes(joke_id):
        return Like.query.filter_by(joke_id=joke_id).count()

    jokes = Joke.query.order_by(Joke.pub_date.desc()).all()
    jokes_list = [{'id': joke.id,
                   'title': joke.title,
                   'text': joke.text,
                   'tags': joke.tags,
                   'userId': joke.user_id,
                   'date': joke.pub_date,
                   'likes': find_likes(joke.id)}
                  for joke in jokes]

    return jsonify({'jokes': jokes_list}), 200


@app.route('/users', methods=['GET'])
def index():
    users = User.query.all()
    users_list = [{'id': user.id,
                   'username': user.username,
                   'email': user.email}
                  for user in users]

    return jsonify({'users': users_list}), 200


# Маршрут для получения имени пользователя по его id
@app.route('/user/<int:user_id>', methods=['GET'])
def get_username(user_id):
    user = User.query.filter_by(id=user_id).first()
    if user:
        return jsonify({'username': user.username}), 200
    else:
        return jsonify({'username': 'Unknown'}), 200


@app.route('/check-admin', methods=['GET'])
@jwt_required(optional=True)
def check_admin():
    user_id = get_jwt_identity()
    user = User.query.filter_by(id=user_id).first()
    if user and user.is_admin:
        return jsonify({'isAdmin': 'true'}), 200
    else:
        return jsonify({'isAdmin': 'false'}), 200


@app.route('/delete-joke/<int:joke_id>', methods=['DELETE'])
@jwt_required()
def delete_joke(joke_id):
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)

    if not user.is_admin:
        return jsonify({'message': 'Access denied'}), 403

    joke = Joke.query.get(joke_id)
    if not joke:
        return jsonify({'message': 'Joke not found'}), 404

    db.session.delete(joke)
    db.session.commit()
    return jsonify({'message': 'Joke deleted successfully!'}), 200


@app.route('/like-post/<int:joke_id>', methods=['POST'])
@jwt_required(optional=True)
def add_like(joke_id):
    current_user_id = get_jwt_identity()
    if not current_user_id:
        return jsonify({'message': 'You need to be signed in to like posts!'}), 401

    like = Like.query.filter_by(user_id=current_user_id, joke_id=joke_id).first()
    if like:
        db.session.delete(like)
        db.session.commit()
        return jsonify({'message': 'Like removed successfully!'}), 201
    else:
        new_like = Like(user_id=current_user_id, joke_id=joke_id)
        db.session.add(new_like)
        db.session.commit()
        return jsonify({'message': 'Like added successfully!'}), 201


@app.route('/is-liked/<int:joke_id>', methods=['GET'])
@jwt_required()
def get_is_liked_for_joke(joke_id):
    joke = Joke.query.get(joke_id)
    current_user_id = get_jwt_identity()
    like = Like.query.filter_by(user_id=current_user_id, joke_id=joke_id).first()
    if joke and like:
        return jsonify({'is_liked': 'true'}), 200
    else:
        return jsonify({'is_liked': 'false'}), 200


@app.route('/top-jokes', methods=['GET'])
def get_top_jokes():
    def find_likes(joke_id):
        return Like.query.filter_by(joke_id=joke_id).count()

    top_jokes = (
        db.session.query(Joke, db.func.count(Like.id).label('like_count'))
        .outerjoin(Like, Joke.id == Like.joke_id)
        .group_by(Joke.id)
        .order_by(db.func.count(Like.id).desc())
        .limit(10)
        .all()
    )

    jokes_list = [{'id': joke.id,
                   'title': joke.title,
                   'text': joke.text,
                   'tags': joke.tags,
                   'userId': joke.user_id,
                   'date': joke.pub_date,
                   'likes': find_likes(joke.id)}
                  for joke, like_count in top_jokes]

    return jsonify({'jokes': jokes_list})


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=8008)
