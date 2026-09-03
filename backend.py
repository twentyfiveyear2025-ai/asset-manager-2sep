from flask import Flask, jsonify, request, send_from_directory, session
from flask_cors import CORS
import hashlib
import json
import os
import secrets
import uuid
from datetime import datetime, timedelta


app = Flask(__name__)
CORS(app, supports_credentials=True)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=False
)


ASSETS_FILE = 'assets.json'
USERS_FILE = 'users.json'
REPORTS_FILE = 'reports.json'
SECURITY_FILE = 'security.json'

assets = []
users = []
reports = []
security_entries = []

SECURITY_LOG_RETENTION_DAYS = 90


def read_json_file(path, default):
    if not os.path.exists(path):
        return default
    try:
        with open(path, 'r', encoding='utf-8') as file:
            return json.load(file)
    except (json.JSONDecodeError, OSError):
        return default


def write_json_file(path, data):
    with open(path, 'w', encoding='utf-8') as file:
        json.dump(data, file, indent=2)


def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


def now_iso():
    return datetime.now().isoformat()


def security_cutoff():
    return datetime.now() - timedelta(days=SECURITY_LOG_RETENTION_DAYS)


def is_recent_security_entry(entry):
    updated_at = entry.get('updated_at')
    if not updated_at:
        return False
    try:
        return datetime.fromisoformat(updated_at) >= security_cutoff()
    except ValueError:
        return False


def prune_security_entries():
    global security_entries
    security_entries = [entry for entry in security_entries if is_recent_security_entry(entry)]


def sanitize_user(user):
    return {key: value for key, value in user.items() if key != 'password'}


def load_data():
    global assets, users, reports, security_entries
    assets = read_json_file(ASSETS_FILE, [])
    users = read_json_file(USERS_FILE, [])
    reports = read_json_file(REPORTS_FILE, [])
    security_entries = read_json_file(SECURITY_FILE, [])
    prune_security_entries()


def save_data():
    prune_security_entries()
    write_json_file(ASSETS_FILE, assets)
    write_json_file(USERS_FILE, users)
    write_json_file(REPORTS_FILE, reports)
    write_json_file(SECURITY_FILE, security_entries)


def display_name(user):
    if not user:
        return 'System'
    return user.get('name') or user.get('username') or 'System'


def append_security_log(title, details, actor='System', asset_id=''):
    prune_security_entries()
    security_entries.insert(0, {
        'id': str(uuid.uuid4()),
        'title': title.strip(),
        'details': details.strip(),
        'actor': actor.strip() or 'System',
        'asset_id': asset_id.strip(),
        'updated_at': now_iso()
    })


def asset_change_notes(before, after):
    field_labels = {
        'name': 'Laptop Name',
        'system_model': 'System Model',
        'generation': 'Gen',
        'user': 'Assigned User',
        'employee_id': 'Employee ID',
        'dept': 'Department',
        'location': 'Location',
        'ram': 'RAM',
        'rom': 'ROM',
        'serial_number': 'Serial Number',
        'bitdefender_installed': 'Bitdefender Installed',
        'policy_name': 'Policy Name',
        'notes': 'Notes',
    }

    changes = []
    for field, label in field_labels.items():
        old_value = (before.get(field) or '').strip()
        new_value = (after.get(field) or '').strip()
        if old_value == new_value:
            continue
        old_text = old_value or 'Blank'
        new_text = new_value or 'Blank'
        changes.append(f'{label} changed from "{old_text}" to "{new_text}"')
    return changes


def asset_summary(asset):
    return ', '.join([
        f'Laptop Name="{(asset.get("name") or "").strip() or "Blank"}"',
        f'System Model="{(asset.get("system_model") or "").strip() or "Blank"}"',
        f'Gen="{(asset.get("generation") or "").strip() or "Blank"}"',
        f'Assigned User="{(asset.get("user") or "").strip() or "Blank"}"',
        f'Employee ID="{(asset.get("employee_id") or "").strip() or "Blank"}"',
        f'Department="{(asset.get("dept") or "").strip() or "Blank"}"',
        f'Location="{(asset.get("location") or "").strip() or "Blank"}"',
        f'RAM="{(asset.get("ram") or "").strip() or "Blank"}"',
        f'ROM="{(asset.get("rom") or "").strip() or "Blank"}"',
        f'Serial Number="{(asset.get("serial_number") or "").strip() or "Blank"}"',
        f'Bitdefender Installed="{(asset.get("bitdefender_installed") or "").strip() or "Blank"}"',
        f'Policy Name="{(asset.get("policy_name") or "").strip() or "Blank"}"',
        f'Notes="{(asset.get("notes") or "").strip() or "Blank"}"',
    ])


def ensure_default_admin():
    global users
    if users:
        return
    users = [{
        'id': str(uuid.uuid4()),
        'username': 'admin',
        'password': hash_password('admin123'),
        'email': 'admin@company.com',
        'role': 'admin',
        'name': 'Admin',
        'employee_id': 'ADM0001',
        'created_at': now_iso(),
        'last_login': None
    }]
    save_data()


def ensure_default_records():
    global reports, security_entries

    changed = False

    legacy_titles = {'Endpoint Audit', 'Access Review'}
    cleaned_security = [
        entry for entry in security_entries
        if entry.get('title') not in legacy_titles
    ]
    if len(cleaned_security) != len(security_entries):
        security_entries = cleaned_security
        changed = True

    if not reports:
        reports = [
            {
                'id': str(uuid.uuid4()),
                'title': 'Quarterly Inventory Note',
                'content': 'Cross-check all newly added laptops against employee onboarding records.',
                'updated_at': now_iso()
            },
            {
                'id': str(uuid.uuid4()),
                'title': 'Pending Follow-up',
                'content': 'Review laptop RAM, ROM, and Bitdefender policy details before closing April review.',
                'updated_at': now_iso()
            }
        ]
        changed = True

    if changed:
        save_data()


def check_auth():
    user_id = session.get('user_id')
    if not user_id:
        return None
    return next((user for user in users if user['id'] == user_id), None)


def require_auth():
    user = check_auth()
    if not user:
        return jsonify({'error': 'Authentication required'}), 401
    return user


def require_admin():
    user = require_auth()
    if isinstance(user, tuple):
        return user
    if user.get('role') != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    return user


def normalize_asset(data, existing=None):
    existing = existing or {}
    asset_id = str(data.get('id', existing.get('id', ''))).strip().upper()
    if asset_id.isdigit():
        asset_id = f'AGS{int(asset_id):04d}'
    return {
        'id': asset_id or existing.get('id', ''),
        'name': data.get('name', existing.get('name', '')).strip(),
        'system_model': data.get('system_model', existing.get('system_model', '')).strip(),
        'generation': data.get('generation', existing.get('generation', '')).strip(),
        'user': data.get('user', existing.get('user', '')).strip(),
        'employee_id': data.get('employee_id', existing.get('employee_id', '')).strip(),
        'dept': data.get('dept', existing.get('dept', '')).strip(),
        'location': data.get('location', existing.get('location', '')).strip(),
        'ram': data.get('ram', existing.get('ram', '')).strip(),
        'rom': data.get('rom', existing.get('rom', '')).strip(),
        'serial_number': data.get('serial_number', existing.get('serial_number', '')).strip(),
        'bitdefender_installed': data.get('bitdefender_installed', existing.get('bitdefender_installed', 'No')).strip() or 'No',
        'policy_name': data.get('policy_name', existing.get('policy_name', '')).strip(),
        'notes': data.get('notes', existing.get('notes', '')).strip(),
        'updated_at': now_iso(),
        'created_at': existing.get('created_at', now_iso())
    }


def next_asset_id():
    numbers = set()
    for asset in assets:
        asset_id = asset.get('id', '')
        if asset_id.startswith('AGS') and asset_id[3:].isdigit():
            numbers.add(int(asset_id[3:]))
    next_number = 1
    while next_number in numbers:
        next_number += 1
    return f'AGS{next_number:04d}'


def find_user_by_username(username):
    lowered = username.lower()
    return next((user for user in users if user['username'].lower() == lowered), None)


load_data()
ensure_default_admin()
ensure_default_records()


@app.route('/auth/login', methods=['POST'])
def login():
    data = request.get_json() or {}
    username = (data.get('username') or '').strip()
    password = data.get('password') or ''

    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400

    hashed_password = hash_password(password)
    user = next(
        (item for item in users if item['username'] == username and item['password'] == hashed_password),
        None
    )
    if not user:
        return jsonify({'error': 'Invalid credentials'}), 401

    user['last_login'] = now_iso()
    session['user_id'] = user['id']
    append_security_log(
        'Login',
        f'{display_name(user)} logged in.',
        actor=display_name(user)
    )
    save_data()
    return jsonify({'user': sanitize_user(user), 'message': 'Login successful'})


@app.route('/auth/logout', methods=['POST'])
def logout():
    user = check_auth()
    if user:
        append_security_log(
            'Logout',
            f'{display_name(user)} logged out.',
            actor=display_name(user)
        )
        save_data()
    session.pop('user_id', None)
    return jsonify({'message': 'Logout successful'})


@app.route('/auth/me', methods=['GET'])
def get_current_user():
    user = check_auth()
    if not user:
        return jsonify({'error': 'Not authenticated'}), 401
    return jsonify(sanitize_user(user))


@app.route('/auth/register', methods=['POST'])
def register():
    data = request.get_json() or {}
    username = (data.get('username') or '').strip()
    email = (data.get('email') or '').strip()
    password = data.get('password') or ''
    name = (data.get('name') or '').strip()

    if not username or not email or not password or not name:
        return jsonify({'error': 'Username, email, password, and name are required'}), 400
    if find_user_by_username(username):
        return jsonify({'error': 'Username already exists'}), 400

    user = {
        'id': str(uuid.uuid4()),
        'username': username,
        'password': hash_password(password),
        'email': email,
        'role': 'employee',
        'name': name,
        'employee_id': data.get('employee_id', '').strip(),
        'number': data.get('number', '').strip(),
        'created_at': now_iso(),
        'last_login': None
    }
    users.append(user)
    save_data()

    session['user_id'] = user['id']
    return jsonify({'user': sanitize_user(user), 'message': 'Registration successful'}), 201


@app.route('/users', methods=['GET'])
def get_users():
    admin_check = require_admin()
    if isinstance(admin_check, tuple):
        return admin_check
    return jsonify([sanitize_user(user) for user in users])


@app.route('/users', methods=['POST'])
def create_user():
    admin_check = require_admin()
    if isinstance(admin_check, tuple):
        return admin_check

    data = request.get_json() or {}
    username = (data.get('username') or '').strip()
    name = (data.get('name') or '').strip()
    email = (data.get('email') or '').strip()
    employee_id = (data.get('employee_id') or '').strip()
    number = (data.get('number') or '').strip()
    role = (data.get('role') or 'employee').strip() or 'employee'

    if not username or not name or not email or not employee_id or not number:
        return jsonify({'error': 'Username, name, email, number, and ID are required'}), 400
    if find_user_by_username(username):
        return jsonify({'error': 'Username already exists'}), 400
    if any(user.get('employee_id', '').lower() == employee_id.lower() for user in users if user.get('employee_id')):
        return jsonify({'error': 'ID already exists'}), 400

    user = {
        'id': str(uuid.uuid4()),
        'username': username,
        'password': hash_password(employee_id),
        'email': email,
        'role': role,
        'name': name,
        'employee_id': employee_id,
        'number': number,
        'created_at': now_iso(),
        'last_login': None
    }
    users.append(user)
    save_data()
    return jsonify(sanitize_user(user)), 201


@app.route('/users/<user_id>', methods=['PUT'])
def update_user(user_id):
    admin_check = require_admin()
    if isinstance(admin_check, tuple):
        return admin_check

    user = next((item for item in users if item['id'] == user_id), None)
    if not user:
        return jsonify({'error': 'User not found'}), 404

    data = request.get_json() or {}
    username = (data.get('username') or user['username']).strip()
    employee_id = (data.get('employee_id') or user.get('employee_id', '')).strip()

    for other in users:
        if other['id'] != user_id and other['username'].lower() == username.lower():
            return jsonify({'error': 'Username already exists'}), 400
        if (
            employee_id and
            other['id'] != user_id and
            other.get('employee_id', '').lower() == employee_id.lower()
        ):
            return jsonify({'error': 'ID already exists'}), 400

    user['username'] = username
    user['name'] = (data.get('name') or user.get('name', '')).strip()
    user['email'] = (data.get('email') or user.get('email', '')).strip()
    user['number'] = (data.get('number') or user.get('number', '')).strip()
    user['role'] = (data.get('role') or user.get('role', 'employee')).strip() or 'employee'
    user['employee_id'] = employee_id

    if data.get('reset_login_to_id') and employee_id:
        user['password'] = hash_password(employee_id)

    save_data()
    return jsonify(sanitize_user(user))


@app.route('/users/<user_id>', methods=['DELETE'])
def delete_user(user_id):
    admin_check = require_admin()
    if isinstance(admin_check, tuple):
        return admin_check

    current_user = check_auth()
    if current_user and current_user['id'] == user_id:
        return jsonify({'error': 'Cannot delete your own account'}), 400

    global users
    users = [user for user in users if user['id'] != user_id]
    save_data()
    return '', 204


@app.route('/assets', methods=['GET'])
def get_assets():
    auth_check = require_auth()
    if isinstance(auth_check, tuple):
        return auth_check
    return jsonify(assets)


@app.route('/assets', methods=['POST'])
def add_asset():
    auth_check = require_auth()
    if isinstance(auth_check, tuple):
        return auth_check

    data = request.get_json() or {}
    asset_id = str(data.get('id', '')).strip().upper()
    if asset_id.isdigit():
        asset_id = f'AGS{int(asset_id):04d}'
    asset_id = asset_id or next_asset_id()
    if any(asset['id'] == asset_id for asset in assets):
        return jsonify({'error': 'Asset ID already exists'}), 400

    asset = normalize_asset({**data, 'id': asset_id})
    if not asset['name']:
        asset['name'] = f'PC {asset_id}'
    assets.append(asset)
    append_security_log(
        'Laptop Created',
        f'{display_name(auth_check)} created {asset_id} for "{asset.get("name")}".',
        actor=display_name(auth_check),
        asset_id=asset_id
    )
    save_data()
    return jsonify(asset), 201


@app.route('/assets/<asset_id>', methods=['PUT'])
def update_asset(asset_id):
    auth_check = require_auth()
    if isinstance(auth_check, tuple):
        return auth_check

    asset = next((item for item in assets if item['id'] == asset_id), None)
    if not asset:
        return jsonify({'error': 'Asset not found'}), 404

    incoming_id = str((request.get_json() or {}).get('id', asset['id'])).strip().upper()
    if incoming_id.isdigit():
        incoming_id = f'AGS{int(incoming_id):04d}'
    incoming_id = incoming_id or asset['id']
    if any(item['id'] == incoming_id and item is not asset for item in assets):
        return jsonify({'error': 'Asset ID already exists'}), 400

    before_asset = dict(asset)
    updated_asset = normalize_asset({**(request.get_json() or {}), 'id': incoming_id}, existing=asset)
    asset.update(updated_asset)

    actor = display_name(auth_check)
    changes = asset_change_notes(before_asset, asset)
    detail = '; '.join(changes) if changes else 'No field-level differences detected, but the laptop record was saved'
    append_security_log(
        'Laptop Update',
        f'{actor} saved {asset.get("id", asset_id)}: {detail}. Snapshot: {asset_summary(asset)}.',
        actor=actor,
        asset_id=asset.get('id', asset_id)
    )

    save_data()
    return jsonify(asset)


@app.route('/assets/<asset_id>', methods=['DELETE'])
def delete_asset(asset_id):
    auth_check = require_auth()
    if isinstance(auth_check, tuple):
        return auth_check

    asset = next((item for item in assets if item['id'] == asset_id), None)
    if not asset:
        return jsonify({'error': 'Asset not found'}), 404

    actor = display_name(auth_check)
    assets.remove(asset)
    append_security_log(
        'Laptop Deleted',
        f'{actor} deleted {asset_id} for "{asset.get("name") or "Unnamed Laptop"}".',
        actor=actor,
        asset_id=asset_id
    )
    save_data()
    return '', 204


@app.route('/security', methods=['GET'])
def get_security_entries():
    auth_check = require_auth()
    if isinstance(auth_check, tuple):
        return auth_check
    return jsonify(security_entries)


@app.route('/security', methods=['POST'])
def create_security_entry():
    return jsonify({'error': 'Security log entries are generated automatically'}), 405


@app.route('/security/<entry_id>', methods=['PUT'])
def update_security_entry(entry_id):
    return jsonify({'error': 'Security log entries cannot be edited'}), 405


@app.route('/security/<entry_id>', methods=['DELETE'])
def delete_security_entry(entry_id):
    return jsonify({'error': 'Security log entries cannot be deleted'}), 405


@app.route('/reports', methods=['GET'])
def get_reports():
    auth_check = require_auth()
    if isinstance(auth_check, tuple):
        return auth_check
    return jsonify(reports)


@app.route('/reports', methods=['POST'])
def create_report():
    auth_check = require_auth()
    if isinstance(auth_check, tuple):
        return auth_check

    data = request.get_json() or {}
    title = (data.get('title') or '').strip()
    if not title:
        return jsonify({'error': 'Note title is required'}), 400

    report = {
        'id': str(uuid.uuid4()),
        'title': title,
        'content': (data.get('content') or '').strip(),
        'updated_at': now_iso()
    }
    reports.append(report)
    save_data()
    return jsonify(report), 201


@app.route('/reports/<report_id>', methods=['PUT'])
def update_report(report_id):
    auth_check = require_auth()
    if isinstance(auth_check, tuple):
        return auth_check

    report = next((item for item in reports if item['id'] == report_id), None)
    if not report:
        return jsonify({'error': 'Note not found'}), 404

    data = request.get_json() or {}
    report['title'] = (data.get('title') or report.get('title', '')).strip()
    report['content'] = (data.get('content') or report.get('content', '')).strip()
    report['updated_at'] = now_iso()
    save_data()
    return jsonify(report)


@app.route('/reports/<report_id>', methods=['DELETE'])
def delete_report(report_id):
    auth_check = require_auth()
    if isinstance(auth_check, tuple):
        return auth_check

    global reports
    reports = [item for item in reports if item['id'] != report_id]
    save_data()
    return '', 204


@app.route('/')
@app.route('/<path:path>')
def serve_frontend(path=''):
    return send_from_directory('.', 'asset.html')


if __name__ == '__main__':
    port = int(os.environ.get('PORT', '5000'))
    app.run(host='0.0.0.0', port=port, debug=False)
