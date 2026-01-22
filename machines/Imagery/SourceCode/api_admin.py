from flask import Blueprint, request, jsonify, session, send_from_directory
from config import *
from utils import *
from datetime import datetime, timedelta
import os
from utils import _load_data, _save_data, _hash_password, _log_event, _generate_display_id, _sanitize_input, _process_path_input

bp_admin = Blueprint('bp_admin', __name__)

@bp_admin.route('/report_bug', methods=['POST'])
def report_bug():
    if 'username' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized. Please log in.'}), 401
    request_payload = request.get_json()
    bug_name = _sanitize_input(request_payload.get('bugName'), 'text', max_length=255)
    bug_details = request_payload.get('bugDetails')
    if not bug_name or not bug_details:
        return jsonify({'success': False, 'message': 'Bug name and details are required.'}), 400
    application_data = _load_data()
    bug_id = str(uuid.uuid4())
    new_bug_report = {
        'id': bug_id,
        'name': bug_name,
        'details': bug_details,
        'reporter': session['username'],
        'reporterDisplayId': session['displayId'],
        'timestamp': datetime.now().isoformat()
    }
    application_data['bug_reports'].append(new_bug_report)
    _save_data(application_data)
    return jsonify({'success': True, 'message': 'Bug report submitted. Admin review in progress. '}), 200

@bp_admin.route('/admin/users', methods=['GET'])
def admin_get_users():
    if not session.get('isAdmin') or session.get('is_impersonating_testuser'):
        return jsonify({'success': False, 'message': 'Access denied. Administrator privileges required.'}), 403
    application_data = _load_data()
    users_data = []
    any_admin_exists = False
    for user in application_data['users']:
        users_data.append({
            'username': user['username'],
            'displayId': user['displayId'],
            'isAdmin': user.get('isAdmin', False),
            'isTestuser': user.get('isTestuser', False)
        })
        if user.get('isAdmin', False):
            any_admin_exists = True
    return jsonify({'success': True, 'users': users_data, 'anyAdminExists': any_admin_exists}), 200

@bp_admin.route('/admin/delete_user', methods=['POST'])
def admin_delete_user():
    if not session.get('isAdmin') or session.get('is_impersonating_testuser'):
        return jsonify({'success': False, 'message': 'Access denied. Administrator privileges required.'}), 403
    request_payload = request.get_json()
    username_to_delete = request_payload.get('username')
    if not username_to_delete:
        return jsonify({'success': False, 'message': 'Username to delete is required.'}), 400
    application_data = _load_data()
    admin_users = [u for u in application_data['users'] if u.get('isAdmin', False)]
    if username_to_delete == session['username'] and len(admin_users) == 1 and session['username'] == admin_users[0]['username']:
        return jsonify({'success': False, 'message': 'Cannot delete the only administrator account while logged in as that account.'}), 403
    user_found = False
    initial_user_count = len(application_data['users'])
    application_data['users'] = [u for u in application_data['users'] if u['username'] != username_to_delete]
    if len(application_data['users']) < initial_user_count:
        user_found = True
        _save_data(application_data)
        return jsonify({'success': True, 'message': f'User {username_to_delete} deleted successfully.'}), 200
    return jsonify({'success': False, 'message': 'User not found.'}), 404

@bp_admin.route('/admin/bug_reports', methods=['GET'])
def admin_get_bug_reports():
    if not session.get('isAdmin') or session.get('is_impersonating_testuser'):
        return jsonify({'success': False, 'message': 'Access denied. Administrator privileges required.'}), 403
    application_data = _load_data()
    bug_reports_data = application_data.get('bug_reports', [])
    return jsonify({'success': True, 'bug_reports': bug_reports_data}), 200

@bp_admin.route('/admin/delete_bug_report', methods=['POST'])
def admin_delete_bug_report():
    if not session.get('isAdmin') or session.get('is_impersonating_testuser'):
        return jsonify({'success': False, 'message': 'Access denied. Administrator privileges required.'}), 403
    request_payload = request.get_json()
    report_id_to_delete = request_payload.get('reportId')
    if not report_id_to_delete:
        return jsonify({'success': False, 'message': 'Bug report ID is required.'}), 400
    application_data = _load_data()
    initial_report_count = len(application_data['bug_reports'])
    application_data['bug_reports'] = [r for r in application_data['bug_reports'] if r['id'] != report_id_to_delete]
    if len(application_data['bug_reports']) < initial_report_count:
        _save_data(application_data)
        return jsonify({'success': True, 'message': 'Bug report deleted successfully.'}), 200
    return jsonify({'success': False, 'message': 'Bug report not found.'}), 404

@bp_admin.route('/admin/impersonate_testuser', methods=['POST'])
def admin_impersonate_testuser():
    if not session.get('isAdmin') or session.get('is_impersonating_testuser'):
        return jsonify({'success': False, 'message': 'Access denied. Administrator privileges required or already impersonating.'}), 403
    request_payload = request.get_json()
    password = request_payload.get('password')
    application_data = _load_data()
    testuser_account = next((u for u in application_data['users'] if u['username'] == 'testuser@imagery.com'), None)
    if not testuser_account:
        return jsonify({'success': False, 'message': 'Testuser account does not exist. Please create it manually.'}), 404
    if testuser_account.get('locked_until'):
        try:
            locked_until_time = datetime.fromisoformat(testuser_account['locked_until'])
            if datetime.now() < locked_until_time:
                return jsonify({'success': False, 'message': 'Testuser account is blocked and try again sometime later.'}), 429
            else:
                testuser_account['failed_login_attempts'] = 0
                testuser_account['locked_until'] = None
                _save_data(application_data)
        except ValueError:
            testuser_account['locked_until'] = None
            testuser_account['failed_login_attempts'] = 0
            _save_data(application_data)
            return jsonify({'success': False, 'message': 'Account state corrupted, please try again.'}), 500
    hashed_input_password = _hash_password(password)
    if testuser_account['password'] == hashed_input_password:
        session['original_admin_username'] = session['username']
        session['original_admin_displayId'] = session['displayId']
        session['original_admin_is_admin'] = session['isAdmin']
        session['username'] = testuser_account['username']
        session['displayId'] = testuser_account['displayId']
        session['isAdmin'] = testuser_account['isAdmin']
        session['is_testuser_account'] = testuser_account.get('isTestuser', False)
        session['is_impersonating_testuser'] = True
        return jsonify({'success': True, 'message': 'Successfully logged in as testuser.'}), 200
    else:
        testuser_account['failed_login_attempts'] = testuser_account.get('failed_login_attempts', 0) + 1
        if testuser_account['failed_login_attempts'] >= MAX_LOGIN_ATTEMPTS:
            testuser_account['locked_until'] = (datetime.now() + timedelta(minutes=ACCOUNT_LOCKOUT_DURATION_MINS)).isoformat()
            _save_data(application_data)
            return jsonify({'success': False, 'message': 'Testuser account is blocked and try again sometime later.'}), 401
        _save_data(application_data)
        return jsonify({'success': False, 'message': 'Invalid password for testuser.'}), 401

@bp_admin.route('/admin/return_to_admin', methods=['POST'])
def admin_return_to_admin():
    if 'original_admin_username' not in session:
        return jsonify({'success': False, 'message': 'Not currently impersonating a user.'}), 400
    original_admin_username = session.pop('original_admin_username')
    original_admin_displayId = session.pop('original_admin_displayId')
    original_admin_is_admin = session.pop('original_admin_is_admin')
    session['username'] = original_admin_username
    session['displayId'] = original_admin_displayId
    session['isAdmin'] = original_admin_is_admin
    session['is_testuser_account'] = False
    session['is_impersonating_testuser'] = False
    return jsonify({'success': True, 'message': 'Returned to admin session.'}), 200

@bp_admin.route('/admin/get_system_log', methods=['GET'])
def get_system_log():
    if not session.get('isAdmin') or session.get('is_impersonating_testuser'):
        return jsonify({'success': False, 'message': 'Access denied. Administrator privileges required.'}), 403
    requested_log_file = request.args.get('log_identifier')
    if not requested_log_file:
        return jsonify({'success': False, 'message': 'Log file identifier is required.'}), 400
    sanitized_log_file_for_show = _process_path_input(requested_log_file)
    full_log_path = os.path.join(SYSTEM_LOG_FOLDER, requested_log_file)
    try:
        return send_from_directory(
            directory=os.path.dirname(full_log_path),
            path=os.path.basename(full_log_path),
            as_attachment=True,
            mimetype='text/plain'
        )
    except FileNotFoundError:
        return jsonify({'success': False, 'message': 'Log file not found.'}), 404
    except IsADirectoryError:
        return jsonify({'success': False, 'message': 'Cannot read a directory.'}), 400
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error reading file: {str(e)}'}), 500

