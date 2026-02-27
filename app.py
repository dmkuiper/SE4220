'''
MIT License

Copyright (c) 2019 Arshdeep Bahga and Vijay Madisetti

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
'''

#!flask/bin/python
from flask import Flask, jsonify, abort, request, make_response, url_for
from flask import render_template, redirect, session
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
import os
import boto3    
import time
import datetime
from boto3.dynamodb.conditions import Key, Attr
import exifread
import json

load_dotenv()

app = Flask(__name__, static_url_path="/assets", static_folder="assets")
app.secret_key = os.getenv("FLASK_SECRET_KEY")

UPLOAD_FOLDER = os.path.join(app.root_path,'media')
ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg'])
AWS_ACCESS_KEY = os.getenv("AWS_ACCESS_KEY")
AWS_SECRET_KEY = os.getenv("AWS_SECRET_KEY")
REGION = os.getenv("AWS_REGION", "us-east-2")
BUCKET_NAME = os.getenv("BUCKET_NAME", "my-cloud-gallery")

if not app.secret_key:
    raise RuntimeError("FLASK_SECRET_KEY is not set")
if not AWS_ACCESS_KEY or not AWS_SECRET_KEY:
    raise RuntimeError("AWS_ACCESS_KEY/AWS_SECRET_KEY are not set")

dynamodb = boto3.resource('dynamodb', aws_access_key_id=AWS_ACCESS_KEY,
                          aws_secret_access_key=AWS_SECRET_KEY,
                          region_name=REGION)

table = dynamodb.Table('PhotoGallery')
users_table = dynamodb.Table('Users')


def get_current_user():
    """Get current logged-in user from session"""
    return session.get('user_id')


def login_required(f):
    """Decorator to require login"""
    def decorated_function(*args, **kwargs):
        if not get_current_user():
            return redirect('/login')
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.errorhandler(400)
def bad_request(error):
    return make_response(jsonify({'error': 'Bad request'}), 400)


@app.errorhandler(404)
def not_found(error):
    return make_response(jsonify({'error': 'Not found'}), 404)


def getExifData(path_name):
    with open(path_name, 'rb') as f:  # Changed to context manager
        tags = exifread.process_file(f)
    ExifData = {}
    for tag in tags.keys():
        if tag not in ('JPEGThumbnail',
                       'TIFFThumbnail',
                       'Filename',
                       'EXIF MakerNote'):
            key = "%s" % (tag)
            val = "%s" % (tags[tag])
            ExifData[key] = val
    return ExifData


def s3uploading(filename, filenameWithPath, username):
    s3 = boto3.client('s3', aws_access_key_id=AWS_ACCESS_KEY,
                      aws_secret_access_key=AWS_SECRET_KEY)

    bucket = BUCKET_NAME
    path_filename = "photos/" + username + "/" + filename
    print(path_filename)  # Fixed: print statement -> print()
    s3.upload_file(filenameWithPath, bucket, path_filename)
    s3.put_object_acl(ACL='public-read',
                      Bucket=bucket, Key=path_filename)
    return "https://" + BUCKET_NAME + \
            ".s3." + REGION + \
            ".amazonaws.com/" + path_filename


@app.route('/', methods=['GET', 'POST'])
def home_page():
    user_id = get_current_user()
    if not user_id:
        return redirect('/login')
    
    # Get user's photos
    response = table.scan(
        FilterExpression=Attr('UserID').eq(user_id)
    )
    items = response['Items']
    print(items)  # Fixed: print statement -> print()
    return render_template('index.html', photos=items, username=session.get('username'))


@app.route('/add', methods=['GET', 'POST'])
@login_required
def add_photo():
    if request.method == 'POST':
        uploadedFileURL = ''
        user_id = get_current_user()
        username = session.get('username')

        file = request.files['imagefile']
        title = request.form['title']
        tags = request.form['tags']
        description = request.form['description']

        print(title, tags, description)  # Fixed: print statement -> print()
        if file and allowed_file(file.filename):
            filename = file.filename
            filenameWithPath = os.path.join(UPLOAD_FOLDER, filename)
            print(filenameWithPath)  # Fixed: print statement -> print()
            file.save(filenameWithPath)
            uploadedFileURL = s3uploading(filename, filenameWithPath, username)
            ExifData = getExifData(filenameWithPath)
            ts = time.time()
            timestamp = datetime.datetime.\
                        fromtimestamp(ts).\
                        strftime('%Y-%m-%d %H:%M:%S')

            table.put_item(
                Item={
                    "PhotoID": str(int(ts * 1000)),
                    "UserID": user_id,
                    "CreationTime": timestamp,
                    "Title": title,
                    "Description": description,
                    "Tags": tags,
                    "URL": uploadedFileURL,
                    "ExifData": json.dumps(ExifData)
                }
            )

        return redirect('/')
    else:
        return render_template('form.html')


@app.route('/<int:photoID>', methods=['GET'])
@login_required
def view_photo(photoID):
    user_id = get_current_user()
    response = table.scan(
        FilterExpression=Attr('PhotoID').eq(str(photoID)) & Attr('UserID').eq(user_id)
    )
    items = response['Items']
    if not items:
        abort(404)
    print(items[0])  # Fixed: print statement -> print()
    tags = items[0]['Tags'].split(',')
    exifdata = json.loads(items[0]['ExifData'])

    return render_template('photodetail.html',
                           photo=items[0], tags=tags, exifdata=exifdata)


@app.route('/download/<int:photoID>', methods=['GET'])
@login_required
def download_photo(photoID):
    user_id = get_current_user()
    response = table.scan(
        FilterExpression=Attr('PhotoID').eq(str(photoID)) & Attr('UserID').eq(user_id)
    )
    items = response['Items']
    if not items:
        abort(404)
    return redirect(items[0]['URL'])


@app.route('/search', methods=['GET'])
@login_required
def search_page():
    user_id = get_current_user()
    query = request.args.get('query', None)

    response = table.scan(
        FilterExpression=(Attr('Title').contains(str(query)) |
                         Attr('Description').contains(str(query)) |
                         Attr('Tags').contains(str(query))) &
                         Attr('UserID').eq(user_id)
    )
    items = response['Items']
    return render_template('search.html',
                           photos=items, searchquery=query)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        try:
            response = users_table.get_item(Key={'Username': username})
            user = response.get('Item')
            
            if user and check_password_hash(user['Password'], password):
                session['user_id'] = user['UserID']
                session['username'] = user['Username']
                return redirect('/')
            else:
                return render_template('login.html', error='Invalid username or password')
        except Exception as e:
            print(f"Login error: {e}")
            return render_template('login.html', error='Login failed')
    else:
        return render_template('login.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if not username or not password:
            return render_template('signup.html', error='Username and password required')

        if password != confirm_password:
            return render_template('signup.html', error='Passwords do not match')

        try:
            # Check if user exists
            response = users_table.get_item(Key={'Username': username})
            if 'Item' in response:
                return render_template('signup.html', error='Username already exists')

            # Create new user
            user_id = str(int(time.time() * 1000))
            hashed_password = generate_password_hash(password)
            
            users_table.put_item(
                Item={
                    'UserID': user_id,
                    'Username': username,
                    'Password': hashed_password,
                    'CreatedAt': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }
            )

            session['user_id'] = user_id
            session['username'] = username
            return redirect('/')
        except Exception as e:
            print(f"Signup error: {e}")
            return render_template('signup.html', error='Signup failed')
    else:
        return render_template('signup.html')


@app.route('/logout', methods=['GET'])
def logout():
    session.clear()
    return redirect('/login')


if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=5000)