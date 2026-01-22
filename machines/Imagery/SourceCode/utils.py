import json
import os
import uuid
import hashlib
import mimetypes
import re
from datetime import datetime
from urllib.parse import unquote
import ipaddress
from config import *

def _sanitize_input(input_string, field_type, max_length=255):
    if not isinstance(input_string, str):
        return ""
    sanitized_string = input_string.strip()
    if field_type == 'name':
        sanitized_string = re.sub(r'[^a-zA-Z0-9\s\-_@.]', '', sanitized_string)
        if max_length is None:
            max_length = 100
    elif field_type == 'text':
        sanitized_string = re.sub(r'[<>"\'`]', '', sanitized_string)
        if max_length is None:
            max_length = 500
    return sanitized_string[:max_length]

def _load_data():
    if not os.path.exists(DATA_STORE_PATH):
        return {'users': [], 'images': [], 'bug_reports': [], 'image_collections': []}
    with open(DATA_STORE_PATH, 'r') as f:
        data = json.load(f)
    for user in data.get('users', []):
        if 'isTestuser' not in user:
            user['isTestuser'] = False
    return data

def _save_data(data):
    with open(DATA_STORE_PATH, 'w') as f:
        json.dump(data, f, indent=4)

def _hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()

def _log_event(username, event_description):
    timestamp = datetime.now().isoformat()
    log_file_path = os.path.join(SYSTEM_LOG_FOLDER, f"{username}.log")
    with open(log_file_path, 'a') as f:
        f.write(f"[{timestamp}] {event_description}\n")

def allowed_file(filename, allowed_extensions):
    if '.' not in filename:
        return False
    parts = filename.split('.')
    if len(parts) < 2:
        return False
    final_extension = parts[-1].lower()
    if final_extension not in allowed_extensions:
        return False
    for i in range(len(parts) - 1):
        if parts[i].lower() in FORBIDDEN_EXTENSIONS:
            return False
    if len(parts) > 2 and any(ext.lower() in FORBIDDEN_EXTENSIONS for ext in parts[:-1]):
        return False
    return True

def get_file_mimetype(filepath):
    mime_type, _ = mimetypes.guess_type(filepath)
    return mime_type

def _generate_display_id():
    return str(uuid.uuid4())[:8]

def _get_image_details(image_entry):
    return {
        'id': image_entry.get('id'),
        'filename': image_entry.get('filename'),
        'url': image_entry.get('url'),
        'title': image_entry.get('title'),
        'description': image_entry.get('description', 'no description provided'),
        'timestamp': image_entry.get('timestamp'),
        'uploadedBy': image_entry.get('uploadedBy'),
        'uploadedByDisplayId': image_entry.get('uploadedByDisplayId'),
        'group': image_entry.get('group', 'Unsorted'),
        'type': image_entry.get('type', 'original'),
        'actual_mimetype': image_entry.get('actual_mimetype', 'application/octet-stream')
    }

def _is_private_ip(ip_address_str):
    try:
        ip_obj = ipaddress.ip_address(ip_address_str)
        for net in PRIVATE_IP_RANGES:
            if ip_obj in net:
                return True
        return False
    except ValueError:
        return True

def _deobfuscate_url(url):
    try:
        deobfuscated_url = unquote(url)
        if '%' in deobfuscated_url:
            deobfuscated_url = unquote(deobfuscated_url)
        if '\\x' in deobfuscated_url:
            deobfuscated_url = bytes(deobfuscated_url, 'utf-8').decode('unicode_escape')
    except Exception:
        return url
    return deobfuscated_url

def _calculate_file_md5(filepath):
    hash_md5 = hashlib.md5()
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()
    except FileNotFoundError:
        return None
    except Exception:
        return None

def _process_path_input(input_path):
    normalized_input = os.path.normpath(input_path)
    cleaned_path = re.sub(r'\.\.[/\\]', '', normalized_input)
    return cleaned_path
