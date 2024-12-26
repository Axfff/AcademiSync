# app/auth/routes.py
import requests
from flask import Blueprint, request, jsonify
from ..models import db, User
from ..utils import hash_password, verify_password
from flask_jwt_extended import create_access_token
from sqlalchemy.exc import IntegrityError
from config import Config

auth_bp = Blueprint('auth', __name__)

def verify_email_with_hunter(email):
    """Function to verify email using Hunter.io API."""
    params = {
        'email': email,
        'api_key': Config.HUNTER_API_KEY
    }
    response = requests.get(Config.HUNTER_API_URL, params=params)
    if response.status_code == 200:
        data = response.json()
        if data.get('data') and data['data']['status'] == 'valid':
            return True
    return False

@auth_bp.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    email = data.get('email')
    password_hash = data.get('password_hash')
    name = data.get('name')

    if not email or not password_hash or not name:
        return jsonify({'message': 'Missing required fields.'}), 400

    if not email in ['teststudent@university.edu']:  # test email won't be verified
        if not email.endswith('@connect.hkust-gz.edu.cn'):
            return jsonify({'message': 'Please use school email address for registration. Registration is not available if you are not an official student'}), 400
        # Check email validity using Hunter.io
        if not verify_email_with_hunter(email):
            return jsonify({'message': 'Invalid or non-existent email.'}), 400

    # Proceed with user registration if email is valid
    new_user = User(email=email, password_hash=password_hash, name=name)
    try:
        db.session.add(new_user)
        db.session.commit()
        return jsonify({'message': 'Registration successful.'}), 200
    except IntegrityError:
        db.session.rollback()
        return jsonify({'message': 'Email already exists.'}), 400

@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password_hash = data.get('password_hash')

    if not email or not password_hash:
        return jsonify({'message': 'Missing email or password_hash.'}), 400

    user = User.query.filter_by(email=email).first()
    if user and password_hash == user.password_hash:
        token = create_access_token(identity=str(user.id))
        user_data = {
            'id': user.id,
            'email': user.email,
            'name': user.name,
            'created_at': user.created_at.isoformat()
        }
        return jsonify({'token': token, 'user': user_data}), 200
    else:
        return jsonify({'message': 'Invalid email or password_hash.'}), 401
