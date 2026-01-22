from flask import Blueprint, request, jsonify, session
from config import *
from utils import *
from datetime import datetime, timedelta
from utils import _load_data, _save_data, _hash_password, _log_event, _generate_display_id, _sanitize_input

bp_auth = Blueprint('bp_auth', __name__)

@bp_auth.route('/register', methods=['POST'])
def register_user():
    request_payload = request.get_json()
    username = _sanitize_input(request_payload.get('username'), 'name', max_length=50)
    password = request_payload.get('password')
    if not username or not password:
        return jsonify({'success': False, 'message': 'Email-id and password are required.'}), 400
    application_data = _load_data()
    if any(user['username'] == username for user in application_data['users']):
        _log_event(username, "Registration failed (Email-id already exists).")
        return jsonify({'success': False, 'message': 'Email-id already exists.'}), 409
    hashed_password = _hash_password(password)
    display_id = _generate_display_id()
    is_admin = False
    if not application_data['users']:
        is_admin = True
        _log_event(username, "First user registered, assigned as admin.")
    new_user = {
        'username': username,
        'password': hashed_password,
        'displayId': display_id,
        'isAdmin': is_admin,
        'failed_login_attempts': 0,
        'locked_until': None,
        'isTestuser': False
    }
    application_data['users'].append(new_user)
    _save_data(application_data)
    _log_event(username, "Registered successfully.")
    return jsonify({'success': True, 'message': 'Registration successful. You can now log in.'}), 201

@bp_auth.route('/login', methods=['POST'])
def user_authentication():
    request_payload = request.get_json()
    username = request_payload.get('username')
    password = request_payload.get('password')
    if not username or not password:
        return jsonify({'success': False, 'message': 'Username and password are required.'}), 400
    application_data = _load_data()
    current_user_account = next((u for u in application_data['users'] if u['username'] == username), None)
    if current_user_account:
        if current_user_account.get('locked_until'):
            try:
                locked_until_time = datetime.fromisoformat(current_user_account['locked_until'])
                if datetime.now() < locked_until_time:
                    _log_event(username, f"Failed login attempt (account locked).")
                    return jsonify({'success': False, 'message': 'Account is blocked and try again sometime later.'}), 429
                else:
                    current_user_account['failed_login_attempts'] = 0
                    current_user_account['locked_until'] = None
                    _save_data(application_data)
                    _log_event(username, f"Account lockout expired. Failed login attempts reset to 0.")
                    return jsonify({'success': True, 'message': 'Account unlocked. Please try logging in again.'}), 200
            except ValueError:
                _log_event(username, f"Error: Malformed 'locked_until' timestamp for user '{username}'. Resetting lock.")
                current_user_account['locked_until'] = None
                current_user_account['failed_login_attempts'] = 0
                _save_data(application_data)
                return jsonify({'success': False, 'message': 'Account state corrupted, please try again.'}), 500
        hashed_input_password = _hash_password(password)
        if current_user_account['password'] == hashed_input_password:
            session['username'] = username
            session['displayId'] = current_user_account['displayId']
            session['isAdmin'] = current_user_account['isAdmin']
            session['is_testuser_account'] = current_user_account.get('isTestuser', False)
            session['is_impersonating_testuser'] = False
            current_user_account['failed_login_attempts'] = 0
            current_user_account['locked_until'] = None
            _save_data(application_data)
            _log_event(username, "Logged in successfully.")
            return jsonify({'success': True, 'message': 'Login successful.', 'displayId': current_user_account['displayId'], 'isAdmin': current_user_account['isAdmin'], 'isTestuser': current_user_account.get('isTestuser', False)}), 200
        else:
            current_user_account['failed_login_attempts'] = current_user_account.get('failed_login_attempts', 0) + 1
            if current_user_account['failed_login_attempts'] >= MAX_LOGIN_ATTEMPTS:
                current_user_account['locked_until'] = (datetime.now() + timedelta(minutes=ACCOUNT_LOCKOUT_DURATION_MINS)).isoformat()
                _save_data(application_data)
                _log_event(username, f"Failed login attempt. Account locked for {ACCOUNT_LOCKOUT_DURATION_MINS} minutes.")
                return jsonify({'success': False, 'message': 'Account is blocked and try again sometime later.'}), 401
            _save_data(application_data)
            _log_event(username, "Failed login attempt (invalid password).")
            return jsonify({'success': False, 'message': 'Invalid username or password.'}), 401
    else:
        _log_event("unknown_user", f"Failed login attempt for non-existent user: {username}.")
        return jsonify({'success': False, 'message': 'Invalid username or password.'}), 401

@bp_auth.route('/logout', methods=['POST'])
def user_logout():
    username = session.pop('username', None)
    session.pop('displayId', None)
    session.pop('isAdmin', None)
    session.pop('is_testuser_account', None)
    session.pop('is_impersonating_testuser', None)
    if username:
        _log_event(username, "Logged out successfully.")
        return jsonify({'success': True, 'message': 'Logged out successfully.'}), 200
    return jsonify({'success': False, 'message': 'No active session to log out from.'}), 400

@bp_auth.route('/auth_status', methods=['GET'])
def auth_status():
    logged_in = 'username' in session
    username = session.get('username')
    display_id = session.get('displayId')
    is_admin = session.get('isAdmin', False)
    is_testuser = session.get('is_testuser_account', False)
    return jsonify({'loggedIn': logged_in, 'username': username, 'displayId': display_id, 'isAdmin': is_admin, 'isTestuser': is_testuser}), 200

