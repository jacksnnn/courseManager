from flask import Flask, request, jsonify, send_file
from google.cloud import datastore, storage
import requests
import json
from urllib.request import urlopen
from jose import jwt
from authlib.integrations.flask_client import OAuth
import io
app = Flask(__name__)
client = datastore.Client()

USERS = 'user'
COURSES = 'course'
PHOTO_BUCKET = ''
ALGORITHMS = ["RS256"]

CLIENT_ID = ''
CLIENT_SECRET = ''
DOMAIN = ''

#Oauth setup
oauth = OAuth(app)
auth0 = oauth.register(
    'auth0',
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    api_base_url="https://" + DOMAIN,
    access_token_url="https://" + DOMAIN + "/oauth/token",
    authorize_url="https://" + DOMAIN + "/authorize",
    client_kwargs={
        'scope': 'openid profile email',
    },
)
# Error exceptions
class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code

# Handle auth error and return status code
@app.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response

# verify jwt token
def verify_jwt(request):
    if 'Authorization' not in request.headers:
        raise AuthError({"Error": "Unauthorized"}, 401)

    auth_header = request.headers['Authorization'].split()
    # Check if the header is in the correct format
    if len(auth_header) != 2:
        raise AuthError({"code": "invalid_header", "description": "Authorization header must be in the format 'Bearer token'"}, 401)

    token = auth_header[1]
    jsonurl = urlopen("https://" + DOMAIN + "/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())

    # Check if the token is valid
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError as e:
        raise AuthError({"Error": "Unauthorized"}, 401)
    
    # Check if the token is signed with RS256
    if unverified_header.get("alg") != "RS256":
        raise AuthError({"code": "invalid_header", "description": "Invalid header. Use an RS256 signed JWT Access Token"}, 401)

    rsa_key = {}
    # Find the RSA key with the matching kid
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }
    if not rsa_key:
        raise AuthError({"code": "no_rsa_key", "description": "No RSA key in JWKS"}, 401)
    # Decode the token
    try:
        payload = jwt.decode(
            token,
            rsa_key,
            algorithms=ALGORITHMS,
            audience=CLIENT_ID,
            issuer="https://" + DOMAIN + "/"
        )
        print(f"JWT payload: {payload}")

        # Query user by sub 
        query = client.query(kind=USERS)
        query.add_filter('sub', '=', payload['sub'])
        result = list(query.fetch())
        # If user not found, return error
        if not result:
            print(f"User with sub {payload['sub']} not found in Datastore")
            raise AuthError({"code": "user_not_found", "description": "User not found in Datastore"}, 404)

        user = result[0]
        payload['role'] = user['role']
        print(f"User found in Datastore: {user}")
        print(f"User role set to: {payload['role']}")
        return payload
    except jwt.ExpiredSignatureError:
        raise AuthError({"code": "token_expired", "description": "Token is expired"}, 401)
    except jwt.JWTClaimsError:
        raise AuthError({"code": "invalid_claims", "description": "Incorrect claims, please check the audience and issuer"}, 401)
    except Exception as e:
        raise AuthError({"code": "invalid_token", "description": f"Unable to parse authentication token. Error: {str(e)}"}, 401)

# Post request to login new user
@app.route('/users/login', methods=['POST'])
def login_user():
    # Check if the request body is valid
    content = request.get_json()
    if 'username' not in content or 'password' not in content:
        return jsonify({"Error": "The request body is invalid"}), 400
    # Post request to Auth0 to get token
    username = content["username"]
    password = content["password"]
    body = {
        'grant_type': 'password',
        'username': username,
        'password': password,
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET
    }
    headers = {'content-type': 'application/json'}
    url = 'https://' + DOMAIN + '/oauth/token'
    r = requests.post(url, json=body, headers=headers)
    if r.status_code != 200:
        return jsonify({"Error": "Unauthorized"}), 401
    # Get token from response
    response_data = r.json()
    if 'id_token' not in response_data:
        return jsonify({"Error": "Failed to retrieve id_token"}), 500

    return jsonify({"token": response_data['id_token']}), 200

# Get request to get all users
@app.route('/users', methods=['GET'])
def get_all_users():
    # Verify JWT token
    payload = verify_jwt(request)
    print(f"User role from JWT: {payload.get('role')}")
    if payload.get('role') != 'admin':
        return jsonify({"Error": "You don't have permission on this resource"}), 403
    # Query all users
    query = client.query(kind=USERS)
    results = list(query.fetch())
    # Return all users with id, role, and sub
    users = [{'id': user.key.id, 'role': user['role'], 'sub': user['sub']} for user in results]
    return jsonify(users), 200

# Get request to get user by id
@app.route('/users/<int:user_id>', methods=['GET'])
def get_user(user_id):
    # Verify JWT token
    payload = verify_jwt(request)
    user_key = client.key(USERS, user_id)
    user = client.get(key=user_key)
    # If user not found, error
    if user is None:
        return jsonify({"Error": "User not found"}), 404
    # If user is not admin or the user itself, error
    if payload['role'] != 'admin' and payload['sub'] != user['sub']:
        return jsonify({"Error": "You don't have permission on this resource"}), 403
    # Return user info
    user_info = {'id': user.key.id, 'role': user['role'], 'sub': user['sub']}
    if 'avatar_url' in user:
        user_info['avatar_url'] = user['avatar_url']
    # If user is instructor or student, return courses
    if user['role'] in ['instructor', 'student']:
        user_info['courses'] = user.get('courses', [])
    return jsonify(user_info), 200


# Post request to create/update avatar
@app.route('/users/<int:user_id>/avatar', methods=['POST'])
def create_or_update_avatar(user_id):
    # Verify JWT token
    payload = verify_jwt(request)
    user_key = client.key(USERS, user_id)
    user = client.get(key=user_key)
    # If user not found, error
    if user is None:
        return jsonify({"Error": "Not found"}), 404
    # If user is not admin or the user itself, error
    if payload['sub'] != user['sub']:
        return jsonify({"Error": "You don't have permission on this resource"}), 403
    # If file not in request, error
    if 'file' not in request.files:
        return jsonify({"Error": "The request body is invalid"}), 400
    # Upload file to GCS
    file_obj = request.files['file']
    storage_client = storage.Client()
    bucket = storage_client.bucket(PHOTO_BUCKET)
    blob = bucket.blob(f'avatars/{user_id}.png')
    blob.upload_from_file(file_obj)
    # Update user avatar url
    user['avatar_url'] = f'{request.url_root}users/{user_id}/avatar'
    client.put(user)
    return jsonify({'avatar_url': user['avatar_url']}), 200

# Get request to get avatar
@app.route('/users/<int:user_id>/avatar', methods=['GET'])
def get_avatar(user_id):
    # Verify JWT token
    payload = verify_jwt(request)
    user_key = client.key(USERS, user_id)
    user = client.get(key=user_key)
    # If user not found, error
    if user is None:
        return jsonify({"Error": "Not found"}), 404
    # If user is not admin or the user itself, error
    if payload['sub'] != user['sub']:
        return jsonify({"Error": "You don't have permission on this resource"}), 403
    # If avatar url not in user, error
    if 'avatar_url' not in user:
        return jsonify({"Error": "Not found"}), 404
    # Get avatar from GCS
    storage_client = storage.Client()
    bucket = storage_client.bucket(PHOTO_BUCKET)
    blob = bucket.blob(f'avatars/{user_id}.png')
    # If blob not found, error
    if not blob.exists():
        return jsonify({"Error": "Not found"}), 404
    file_obj = io.BytesIO()
    blob.download_to_file(file_obj)
    file_obj.seek(0)
    return send_file(file_obj, mimetype='image/png', download_name=f'{user_id}.png'), 200

# Delete request to delete avatar
@app.route('/users/<int:user_id>/avatar', methods=['DELETE'])
def delete_avatar(user_id):
    # Verify JWT token
    payload = verify_jwt(request)
    user_key = client.key(USERS, user_id)
    user = client.get(key=user_key)
    # If user not found, error
    if user is None:
        return jsonify({"Error": "Not found"}), 404
    # If user is not admin or the user itself, error
    if payload['sub'] != user['sub']:
        return jsonify({"Error": "You don't have permission on this resource"}), 403
    # If avatar url not in user, error
    if 'avatar_url' not in user:
        return jsonify({"Error": "Not found"}), 404
    # Delete avatar from GCS
    storage_client = storage.Client()
    bucket = storage_client.bucket(PHOTO_BUCKET)
    blob = bucket.blob(f'avatars/{user_id}.png')
    blob.delete()
    del user['avatar_url']
    client.put(user)
    return '', 204

# Post request to create new course
@app.route('/courses', methods=['POST'])
def create_course():
    # Verify JWT token
    payload = verify_jwt(request)
    # If user is not admin, error
    if payload['role'] != 'admin':
        return jsonify({"Error": "You don't have permission on this resource"}), 403
    # Check if the request is valid
    content = request.get_json()
    required_fields = ['subject', 'number', 'title', 'term', 'instructor_id']
    if not all(field in content for field in required_fields):
        return jsonify({"Error": "The request body is invalid"}), 400
    # Check if instructor is valid
    instructor_key = client.key(USERS, content['instructor_id'])
    instructor = client.get(key=instructor_key)
    if instructor is None or instructor['role'] != 'instructor':
        return jsonify({"Error": "The request body is invalid"}), 400
    # Create new course
    new_course = datastore.Entity(client.key(COURSES))
    new_course.update(content)
    client.put(new_course)
    new_course['id'] = new_course.key.id
    new_course['self'] = f'{request.url_root}courses/{new_course.key.id}'
    return jsonify(new_course), 201

# Get request to get all courses
@app.route('/courses', methods=['GET'])
def get_courses():
    # Offset and limit for pagination
    offset = int(request.args.get('offset', 0))
    limit = int(request.args.get('limit', 3))
    # Query all courses
    query = client.query(kind=COURSES)
    query.order = ['subject'] 
    query_iter = query.fetch(offset=offset, limit=limit)
    courses = list(query_iter)
    for course in courses:
        course['id'] = course.key.id
        course['self'] = f'{request.url_root}courses/{course.key.id}'
    # Get next url for pagination
    next_offset = offset + limit
    next_url = f'{request.url_root}courses?offset={next_offset}&limit={limit}' if len(courses) == limit else None
    return jsonify({'courses': courses, 'next': next_url}), 200

# Get request to get course by id
@app.route('/courses/<int:course_id>', methods=['GET'])
def get_course(course_id):
    course_key = client.key(COURSES, course_id)
    course = client.get(key=course_key)
    # If course not found, error
    if course is None:
        return jsonify({"Error": "Not found"}), 404
    # Return course info
    course['id'] = course.key.id
    course['self'] = f'{request.url_root}courses/{course.key.id}'
    return jsonify(course), 200

# Patch request to update course
@app.route('/courses/<int:course_id>', methods=['PATCH'])
def update_course(course_id):
    # Verify JWT token
    payload = verify_jwt(request)
    # If user is not admin, error
    if payload['role'] != 'admin':
        return jsonify({"Error": "You don't have permission on this resource"}), 403
    course_key = client.key(COURSES, course_id)
    course = client.get(key=course_key)
    # If course not found, error
    if course is None:
        return jsonify({"Error": "Not found"}), 404
    # Check if the request is valid
    content = request.get_json()
    if 'instructor_id' in content:
        instructor_key = client.key(USERS, content['instructor_id'])
        instructor = client.get(key=instructor_key)
        if instructor is None or instructor['role'] != 'instructor':
            return jsonify({"Error": "The request body is invalid"}), 400
    # Update course
    course.update(content)
    client.put(course)
    course['id'] = course.key.id
    course['self'] = f'{request.url_root}courses/{course.key.id}'
    return jsonify(course), 200

# Delete request to delete course
@app.route('/courses/<int:course_id>', methods=['DELETE'])
def delete_course(course_id):
    # Verify JWT token
    payload = verify_jwt(request)
    # If user is not admin, error
    if payload['role'] != 'admin':
        return jsonify({"Error": "You don't have permission on this resource"}), 403
    course_key = client.key(COURSES, course_id)
    course = client.get(key=course_key)
    # If course not found, error
    if course is None:
        return jsonify({"Error": "Not found"}), 404
    # Delete course
    client.delete(course_key)
    return '', 204

# Patch request to update course students
@app.route('/courses/<int:course_id>/students', methods=['PATCH'])
def update_course_students(course_id):
    # Verify JWT token
    payload = verify_jwt(request)
    # Query course
    course_key = client.key(COURSES, course_id)
    course = client.get(key=course_key)
    # If course not found, error
    if course is None:
        return jsonify({"Error": "Not found"}), 404
    # If user is not admin or instructor, error
    if payload['role'] == 'instructor' and course['instructor_id'] != payload['sub']:
        return jsonify({"Error": "You don't have permission on this resource"}), 403
    # Check if the request is valid
    content = request.get_json()
    if 'add' not in content or 'remove' not in content:
        return jsonify({"Error": "The request body is invalid"}), 400
    add_ids = content['add']
    remove_ids = content['remove']
    # Check if students are valid
    for student_id in add_ids:
        student_key = client.key(USERS, student_id)
        student = client.get(key=student_key)
        if student is None or student['role'] != 'student':
            return jsonify({"Error": "Enrollment data is invalid"}), 409
    # Update course students
    for student_id in remove_ids:
        student_key = client.key(USERS, student_id)
        student = client.get(key=student_key)
        if student is None or student['role'] != 'student':
            return jsonify({"Error": "Enrollment data is invalid"}), 409
    # Update course students
    if 'students' not in course:
        course['students'] = []

    course['students'] = list(set(course['students']) - set(remove_ids))
    course['students'] = list(set(course['students']) | set(add_ids))
    client.put(course)

    return '', 200

# Get request to get course students
@app.route('/courses/<int:course_id>/students', methods=['GET'])
def get_course_students(course_id):
    # Verify JWT token
    payload = verify_jwt(request)
    # Query course
    course_key = client.key(COURSES, course_id)
    course = client.get(key=course_key)
    # If course not found, error
    if course is None:
        return jsonify({"Error": "Not found"}), 404
    # If user is not admin or instructor, error
    if payload['role'] == 'instructor' and course['instructor_id'] != payload['sub']:
        return jsonify({"Error": "You don't have permission on this resource"}), 403
    # Return course students
    return jsonify(course.get('students', [])), 200

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)
