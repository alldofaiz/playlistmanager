from flask import Flask, render_template, request, jsonify, redirect, url_for, make_response
from flask_bcrypt import Bcrypt
import jwt
from datetime import datetime, timedelta, timezone
from pymongo import MongoClient
from flask_login import current_user
import os
from bson import ObjectId
from werkzeug.utils import secure_filename


app = Flask(__name__)

bcrypt = Bcrypt(app)

# Mengganti URL MongoDB sesuai dengan konfigurasi Anda
client = MongoClient('mongodb+srv://alldofaiz:uj2I5Rp5F3uKXxOT@cluster0.ukqu2f8.mongodb.net/?retryWrites=true&w=majority')
db = client['playlistmanager']
users_collection = db['users']
songs_collection = db['songs']

# Secret key for JWT
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['UPLOAD_FOLDER'] = 'uploads'


        
@app.route('/')
def home():
    all_users = users_collection.find()
    return render_template('index.html', users=all_users)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        description = request.form.get('description')
        email = request.form.get('email')
        password = request.form.get('password')
        existing_user = users_collection.find_one({'$or': [{'username': username}, {'email': email}]})
        if existing_user:
            return jsonify({'message': 'Username or email already exists. Please choose another.'})

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        user_data = {
            'username': username,
            'email': email,
            'password': hashed_password,
            'description' : description,
            'profile_pic': '',
            'cover_pic': '',
            'profile_pic_real': 'profile_pics/profile_placeholder.png',
            'profile_cover_real': 'cover_pics/cover_placeholder.jpg'
        }
        users_collection.insert_one(user_data)

        return render_template('login.html')

    return render_template('signup.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template("login.html")

    username = request.form.get('username')
    password = request.form.get('password')

    user = users_collection.find_one({'username': username})

    if user and bcrypt.check_password_hash(user['password'], password):
       
        exp_time = datetime.now(timezone.utc) + timedelta(minutes=30)
        token = jwt.encode({'username': username, 'exp': exp_time}, app.config['SECRET_KEY'])

        response = make_response(redirect(url_for('profile', username=username)))
        response.set_cookie('token', token, httponly=True, secure=True)
        return response
    return jsonify({'message': 'Login Failed, Username or Password is wrong.'})

@app.route('/profile/<username>')
def profile(username):
    token = request.cookies.get('token')
    try:
        decoded_token = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        decoded_username = decoded_token['username']
        user = users_collection.find_one({'username': decoded_username})
        if user and user['username'] == decoded_username:
            songs = songs_collection.find({'username': decoded_username})
            return render_template("profile.html", user=user, songs=songs)
        else:            return jsonify({'message': 'User not found or unauthorized access.'})
    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Token has expired.'})
    except jwt.InvalidTokenError as e:
        print("Invalid Token Error:", e)
        return jsonify({'message': 'Invalid token.'})

@app.route('/editdescription', methods=['POST'])
def edit_description():
    try:
        token = request.cookies.get('token')
        decoded_token = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        decoded_username = decoded_token['username']
        
        new_description = request.form.get('description')
        
        users_collection.update_one({'username': decoded_username}, {'$set': {'description': new_description}})
        
        return jsonify({'success': True, 'message': 'Description updated successfully'})
    except jwt.ExpiredSignatureError:
        return jsonify({'success': False, 'message': 'Token has expired.'})
    except jwt.InvalidTokenError as e:
        return jsonify({'success': False, 'message': f'Invalid token: {str(e)}'})
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error updating description: {str(e)}'})



@app.route('/update_photo', methods=['POST'])
def update_photo():
    try:
        token = request.cookies.get('token')
        decoded_token = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        decoded_username = decoded_token['username']
        user = users_collection.find_one({'username': decoded_username})

        if user and user['username'] == decoded_username:
            if 'editphotoprofile' not in request.files:
                return jsonify({'message': 'No profile picture provided.'}), 400

            profile_pic = request.files['editphotoprofile']

            if profile_pic.filename == '':
                return jsonify({'message': 'No selected file.'}), 400

            upload_folder = 'static/profile_pics'
            if not os.path.exists(upload_folder):
                os.makedirs(upload_folder)

            file_path = os.path.join(upload_folder, secure_filename(profile_pic.filename))
            profile_pic.save(file_path)

            users_collection.update_one({'username': decoded_username}, {'$set': {'profile_pic_real': file_path}})

            updated_image_url = '/'.join(file_path.split('/')[1:])  
            return jsonify({'message': 'Profile picture updated successfully', 'updatedImageUrl': updated_image_url})
        else:
            return jsonify({'message': 'User not found or unauthorized access.'}), 401
    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Token has expired.'}), 401
    except jwt.InvalidTokenError as e:
        print("Invalid Token Error:", e)
        return jsonify({'message': 'Invalid token.'}), 401

@app.route('/addsong', methods=['POST'])
def add_song():
    token = request.cookies.get('token')
    try:
        decoded_token = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        decoded_username = decoded_token['username']
        title = request.form.get('title')
        artist = request.form.get('artist')
        minutes = request.form.get('minutes')
        seconds = request.form.get('seconds')
        link = request.form.get('link')
        song_data = {
            'title': title,
            'artist': artist,
            'minutes': minutes,
            'seconds': seconds,
            'link': link,
            'username': decoded_username
        }
        songs_collection.insert_one(song_data)
        return jsonify({'message': 'Song added successfully'}), 200
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token has expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid token'}), 401

@app.route('/get_songs', methods=['GET'])
def get_songs():
    token = request.cookies.get('token')

    try:
        decoded_token = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        decoded_username = decoded_token['username']
        songs = songs_collection.find({'username': decoded_username})
        song_list = []
        for song in songs:
            song_list.append({
                '_id': str(song['_id']),
                'title': song['title'],
                'artist': song['artist'],
                'minutes': song['minutes'],
                'seconds': song['seconds'],
                'link': song['link']
            })
        return jsonify(song_list)
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token has expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid token'}), 401

@app.route('/deletesong', methods=['POST'])
def delete_song():
    token = request.cookies.get('token')
    try:
        decoded_token = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        decoded_username = decoded_token['username']
        song_id = request.form.get('songId')
        db.songs.delete_one({'_id': ObjectId(song_id), 'username': decoded_username})
        return jsonify({'message': 'Song deleted successfully'}), 200
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token has expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid token'}), 401

@app.route('/profile-view/<username>')
def profileview(username):

    user = users_collection.find_one({'username': username})
    songs = songs_collection.find({'username': username})


    if user:
        return render_template('profile-view.html', user=user, songs=songs)
    else:

        return render_template('profile_not_found.html', username=username )

@app.route('/logout')
def logout():
    response = make_response(redirect(url_for('home')))
    response.delete_cookie('token')
    return response

if __name__ == '__main__':
    app.run(debug=True)