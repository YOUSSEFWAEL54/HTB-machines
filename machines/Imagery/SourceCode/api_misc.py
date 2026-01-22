from flask import Blueprint, send_from_directory, jsonify, session
from config import *
import os
from utils import UPLOAD_FOLDER

bp_misc = Blueprint('bp_misc', __name__)

@bp_misc.route('/uploads/<path:filename>')
def serve_uploaded_file(filename):
    if 'username' not in session:
        return jsonify({'error': 'Unauthorized access'}), 401
    try:
        abs_upload_dir = os.path.abspath(UPLOAD_FOLDER)
        safe_path = os.path.abspath(os.path.join(abs_upload_dir, filename))
        if not safe_path.startswith(abs_upload_dir):
            return jsonify({'error': 'Access denied'}), 403
        if not os.path.isfile(safe_path):
            return jsonify({'error': 'File not found'}), 404
        return send_from_directory(abs_upload_dir, filename)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

