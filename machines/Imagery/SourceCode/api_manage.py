from flask import Blueprint, request, jsonify, session
from utils import _load_data, _save_data, _hash_password, _log_event, _generate_display_id, _sanitize_input, _get_image_details
from config import *
import os
from config import UPLOAD_FOLDER
from utils import _deobfuscate_url

bp_manage = Blueprint('bp_manage', __name__)

@bp_manage.route('/images', methods=['GET'])
def get_images():
    if 'username' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized. Please log in.'}), 401
    try:
        application_data = _load_data()
        username = session.get('username')
        if not username:
            return jsonify({'success': False, 'message': 'Session invalid. Please log in again.'}), 401
        user_images = []
        for img in application_data['images']:
            if isinstance(img, dict) and img.get('uploadedBy') == username:
                try:
                    user_images.append(_get_image_details(img))
                except Exception as e:
                    _log_event(username, f"Error processing image entry {img.get('id', 'N/A')} for gallery display: {e}. Skipping this image.")
                    continue
        grouped_images = {}
        for img_detail in user_images:
            try:
                group_name = img_detail.get('group', 'Unsorted')
                if group_name not in grouped_images:
                    grouped_images[group_name] = []
                grouped_images[group_name].append(img_detail)
            except Exception as e:
                _log_event(username, f"Error grouping image {img_detail.get('id', 'N/A')}: {e}. Skipping this image for grouping.")
                continue
        grouped_images_list = [{'name': name, 'images': images} for name, images in grouped_images.items()]
        response_data = {'success': True, 'images': user_images, 'grouped_images': grouped_images_list}
        return jsonify(response_data), 200
    except FileNotFoundError:
        return jsonify({'success': False, 'message': 'Database file not found.'}), 500
    except Exception as e:
        return jsonify({'success': False, 'message': f'Failed to load images due to an unexpected server error: {e}'}), 500

@bp_manage.route('/edit_image_details', methods=['POST'])
def edit_image_details():
    if not session.get('is_testuser_account'):
        return jsonify({'success': False, 'message': 'Feature is still in development.'}), 403
    if 'username' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized. Please log in.'}), 401
    request_payload = request.get_json()
    image_id = request_payload.get('imageId')
    title = _sanitize_input(request_payload.get('title'), 'text', max_length=255)
    description = _sanitize_input(request_payload.get('description'), 'text', max_length=1000)
    group_name = _sanitize_input(request_payload.get('group_name', 'Unsorted'), 'name', max_length=100)
    if not image_id:
        return jsonify({'success': False, 'message': 'Image ID is required.'}), 400
    application_data = _load_data()
    image_found = False
    for img in application_data['images']:
        if img['id'] == image_id and img['uploadedBy'] == session['username']:
            img['title'] = title
            img['description'] = description
            img['group'] = group_name
            image_found = True
            break
    if image_found:
        _save_data(application_data)
        _log_event(session['username'], f"Edited details for image ID: {image_id}.")
        return jsonify({'success': True, 'message': 'Image details updated successfully!'}), 200
    return jsonify({'success': False, 'message': 'Image not found or unauthorized to edit.'}), 404

@bp_manage.route('/delete_image', methods=['POST'])
def delete_image():
    if 'username' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized. Please log in.'}), 401
    request_payload = request.get_json()
    image_id = request_payload.get('imageId')
    delete_all_derived = request_payload.get('deleteAllDerived', False)
    if not image_id:
        return jsonify({'success': False, 'message': 'Image ID is required.'}), 400
    application_data = _load_data()
    original_image = None
    images_to_delete_ids = set()
    files_to_delete_paths = []
    for img in application_data['images']:
        if img['id'] == image_id and img['uploadedBy'] == session['username']:
            original_image = img
            break
    if not original_image:
        return jsonify({'success': False, 'message': 'Image not found or unauthorized to delete.'}), 404
    if original_image.get('type') == 'original' and delete_all_derived:
        images_to_delete_ids.add(original_image['id'])
        files_to_delete_paths.append(os.path.join(UPLOAD_FOLDER, original_image['filename']))
        for img in application_data['images']:
            if img.get('original_id') == original_image['id']:
                images_to_delete_ids.add(img['id'])
                files_to_delete_paths.append(os.path.join(UPLOAD_FOLDER, img['filename']))
        _log_event(session['username'], f"Initiated deletion of original image {original_image['id']} and all derived copies.")
    else:
        images_to_delete_ids.add(original_image['id'])
        files_to_delete_paths.append(os.path.join(UPLOAD_FOLDER, original_image['filename']))
        _log_event(session['username'], f"Initiated deletion of image {original_image['id']}.")
    application_data['images'] = [img for img in application_data['images'] if img['id'] not in images_to_delete_ids]
    _save_data(application_data)
    for fpath in files_to_delete_paths:
        if os.path.exists(fpath):
            try:
                os.remove(fpath)
                _log_event(session['username'], f"Successfully deleted file: {fpath}.")
            except OSError as e:
                _log_event(session['username'], f"Error deleting file {fpath}: {e}")
    return jsonify({'success': True, 'message': 'Image(s) deleted successfully!'}), 200

@bp_manage.route('/create_image_collection', methods=['POST'])
def create_image_collection():
    if not session.get('is_testuser_account'):
        return jsonify({'success': False, 'message': 'Feature is still in development.'}), 403
    if 'username' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized. Please log in.'}), 401
    request_payload = request.get_json()
    collection_name = _sanitize_input(request_payload.get('collectionName'), 'name', max_length=100)
    if not collection_name:
        return jsonify({'success': False, 'message': 'Collection name is required.'}), 400
    application_data = _load_data()
    if not any(coll['name'].lower() == collection_name.lower() for coll in application_data.get('image_collections', [])):
        application_data.setdefault('image_collections', []).append({'name': collection_name})
        _save_data(application_data)
        _log_event(session['username'], f"Created new image collection: '{collection_name}'.")
        return jsonify({'success': True, 'message': f"Collection '{collection_name}' created successfully."}), 200
    else:
        return jsonify({'success': False, 'message': f"Collection '{collection_name}' already exists."}), 409

@bp_manage.route('/get_image_collections', methods=['GET'])
def get_image_collections():
    if 'username' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized. Please log in.'}), 401
    application_data = _load_data()
    collections = application_data.get('image_collections', [])
    return jsonify({'success': True, 'collections': collections}), 200

@bp_manage.route('/move_images_to_collection', methods=['POST'])
def move_images_to_collection():
    if not session.get('is_testuser_account'):
        return jsonify({'success': False, 'message': 'Feature is still in development.'}), 403
    if 'username' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized. Please log in.'}), 401
    request_payload = request.get_json()
    image_ids = request_payload.get('imageIds', [])
    target_collection_name = _sanitize_input(request_payload.get('targetCollectionName'), 'name', max_length=100)
    if not image_ids or not target_collection_name:
        return jsonify({'success': False, 'message': 'Image IDs and target collection name are required.'}), 400
    application_data = _load_data()
    moved_count = 0
    for img in application_data['images']:
        if img['id'] in image_ids and img['uploadedBy'] == session['username']:
            img['group'] = target_collection_name
            moved_count += 1
    if moved_count > 0:
        _save_data(application_data)
        _log_event(session['username'], f"Moved {moved_count} images to collection: '{target_collection_name}'.")
        return jsonify({'success': True, 'message': f"Successfully moved {moved_count} image(s) to '{target_collection_name}'."}), 200
    else:
        return jsonify({'success': False, 'message': 'No images found or authorized to move.'}), 404

