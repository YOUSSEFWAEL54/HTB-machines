from utils import allowed_file, get_file_mimetype, _sanitize_input, _load_data, _save_data, _log_event, _generate_display_id, _deobfuscate_url, _is_private_ip
from config import ALLOWED_MEDIA_EXTENSIONS, MAX_FILE_SIZE_BYTES, MAX_FILE_SIZE_MB, ALLOWED_UPLOAD_MIME_TYPES
from flask import Blueprint, request, jsonify, session
from werkzeug.utils import secure_filename
from urllib.parse import urlparse
from config import *
import requests
import socket
import ipaddress
from datetime import datetime
import tempfile
import os
import uuid

bp_upload = Blueprint('bp_upload', __name__)

@bp_upload.route('/upload_image', methods=['POST'])
def upload_image():
    if 'username' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized. Please log in.'}), 401
    if 'file' not in request.files:
        return jsonify({'success': False, 'message': 'No file part in the request.'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'success': False, 'message': 'No selected file.'}), 400
    if not allowed_file(file.filename, ALLOWED_MEDIA_EXTENSIONS):
        return jsonify({'success': False, 'message': 'File type not allowed by extension.'}), 400
    file.seek(0, os.SEEK_END)
    file_size = file.tell()
    file.seek(0)
    if file_size > MAX_FILE_SIZE_BYTES:
        return jsonify({'success': False, 'message': f'File size exceeds {MAX_FILE_SIZE_MB}MB limit.'}), 413
    try:
        filename = secure_filename(file.filename)
        unique_filename = f"{uuid.uuid4()}_{filename}"
        filepath = os.path.join(UPLOAD_FOLDER, unique_filename)
        file.save(filepath)
        actual_mimetype = get_file_mimetype(filepath)
        if actual_mimetype not in ALLOWED_UPLOAD_MIME_TYPES:
            os.remove(filepath)
            _log_event(session['username'], f"Blocked upload due to disallowed MIME type: {actual_mimetype} for file {filename}.")
            return jsonify({'success': False, 'message': 'Uploaded file has an unsupported content type.'}), 400
        title = _sanitize_input(request.form.get('title'), 'text', max_length=255)
        if not title:
            title = os.path.splitext(filename)[0]
        description = _sanitize_input(request.form.get('description', 'no description provided'), 'text', max_length=1000)
        group_name = _sanitize_input(request.form.get('group_name', 'Unsorted'), 'name', max_length=100)
        application_data = _load_data()
        image_id = str(uuid.uuid4())
        image_entry = {
            'id': image_id,
            'filename': unique_filename,
            'url': f'/uploads/{unique_filename}',
            'title': title,
            'description': description,
            'timestamp': datetime.now().isoformat(),
            'uploadedBy': session['username'],
            'uploadedByDisplayId': session['displayId'],
            'group': group_name,
            'type': 'original',
            'actual_mimetype': actual_mimetype
        }
        application_data['images'].append(image_entry)
        if not any(coll['name'] == group_name for coll in application_data.get('image_collections', [])):
            application_data.setdefault('image_collections', []).append({'name': group_name})
        _save_data(application_data)
        _log_event(session['username'], f"Uploaded image: {filename} (ID: {image_id}) to group '{group_name}'.")
        return jsonify({'success': True, 'message': 'Image uploaded successfully!', 'imageId': image_id}), 200
    except Exception as e:
        _log_event(session['username'], f"Error uploading image: {str(e)}")
        return jsonify({'success': False, 'message': f'Error uploading image: {str(e)}'}), 500
