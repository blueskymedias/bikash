import os
import json
import psycopg2
import logging
import jwt
import datetime
from flask import Flask, request, jsonify, send_from_directory, send_file
from flask_bcrypt import Bcrypt
from functools import wraps
import random
from typing import Dict, List
from dataclasses import dataclass
from collections import defaultdict

# Initialize Flask app
app = Flask(__name__)

# Configuration
SECRET_KEY = "my-super-secret-key-123"
EXPORT_DIR = os.path.join(os.getcwd(), 'exports', 'timetables')
LOG_DIR = os.path.join(os.getcwd(), 'exports', 'logs')
os.makedirs(EXPORT_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    filename=os.path.join(LOG_DIR, 'app.log'),
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
logger.addHandler(console_handler)

# Database configuration
DB_CONFIG = {
    'host': 'localhost',
    'database': 'postgres',
    'user': 'postgres',
    'password': '1616'
}

# Initialize Bcrypt
bcrypt = Bcrypt(app)

# Database connection
def get_db_connection():
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        logger.debug("Database connection established")
        return conn
    except psycopg2.Error as e:
        logger.error(f"Database connection failed: {e}")
        raise

# Initialize database
def init_db():
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    role TEXT NOT NULL CHECK (role IN ('teacher', 'admin'))
                );
                CREATE TABLE IF NOT EXISTS subjects (
                    id SERIAL PRIMARY KEY,
                    name TEXT NOT NULL,
                    teacher TEXT NOT NULL,
                    max_daily_slots INTEGER DEFAULT 2,
                    preferred_rooms TEXT[],
                    created_by INTEGER REFERENCES users(id)
                );
                CREATE TABLE IF NOT EXISTS timetables (
                    id SERIAL PRIMARY KEY,
                    data JSONB NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    created_by INTEGER REFERENCES users(id),
                    is_deleted BOOLEAN DEFAULT FALSE
                );
            """)
            conn.commit()
            logger.info("Database tables created or verified")
            
            default_users = [
                ('admin', 'admin123', 'admin'),
                ('teacher', 'teacher123', 'teacher')
            ]
            for username, password, role in default_users:
                hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
                cur.execute("""
                    INSERT INTO users (username, password, role)
                    SELECT %s, %s, %s
                    WHERE NOT EXISTS (SELECT 1 FROM users WHERE username = %s);
                """, (username, hashed_password, role, username))
            conn.commit()
            logger.info("Default users initialized")
    except psycopg2.Error as e:
        logger.error(f"Database initialization failed: {e}")
        raise
    finally:
        conn.close()

# Token Management
def generate_token(user_id: int, role: str) -> str:
    payload = {
        'user_id': user_id,
        'role': role,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
    logger.debug(f"Token generated for user_id={user_id}, role={role}")
    return token

def verify_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        logger.debug(f"Token verified: {payload}")
        return payload
    except jwt.ExpiredSignatureError:
        logger.warning("Token has expired")
        return None
    except jwt.InvalidTokenError:
        logger.warning("Invalid token")
        return None

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            logger.warning("No valid Bearer token provided")
            return jsonify({'message': 'Token is missing or invalid'}), 401
        token = auth_header.split(' ')[1]
        payload = verify_token(token)
        if not payload:
            return jsonify({'message': 'Token is invalid or expired'}), 401
        request.user = payload
        return f(*args, **kwargs)
    return decorated

# Timetable Generator
@dataclass
class Subject:
    name: str
    teacher: str
    max_daily_slots: int = 2
    preferred_rooms: List[str] = None

class TimetableGenerator:
    def __init__(self, subjects: List[Subject]):
        self.days = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday']
        self.slots = ['9:00', '10:00', '11:00', '12:00', '14:00', '15:00', '16:00']
        self.rooms = ['Room A', 'Room B', 'Room C']
        self.subjects = subjects

    def generate(self) -> Dict:
        timetable = {day: {} for day in self.days}
        teacher_schedule = defaultdict(set)
        room_schedule = defaultdict(set)
        for day in self.days:
            daily_subjects = defaultdict(int)
            last_subject = None
            for slot in self.slots:
                valid_subjects = [
                    s for s in self.subjects
                    if daily_subjects[s.name] < s.max_daily_slots and
                       (last_subject is None or last_subject.name != s.name) and
                       s.teacher not in teacher_schedule[(day, slot)]
                ]
                if not valid_subjects:
                    timetable[day][slot] = {"subject": "Free", "teacher": "-", "room": "-"}
                    continue
                subject = random.choice(valid_subjects)
                room = self._assign_room(subject, day, slot, room_schedule)
                timetable[day][slot] = {"subject": subject.name, "teacher": subject.teacher, "room": room}
                last_subject = subject
                daily_subjects[subject.name] += 1
                teacher_schedule[(day, slot)].add(subject.teacher)
                if room != "-":
                    room_schedule[(day, slot)].add(room)
        return timetable

    def _assign_room(self, subject: Subject, day: str, slot: str, room_schedule: Dict) -> str:
        if not subject.preferred_rooms:
            return "-"
        for room in subject.preferred_rooms:
            if room not in room_schedule[(day, slot)]:
                return room
        return "-"

# Helper Functions
def get_user_by_username(username: str) -> dict:
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id, username, password, role FROM users WHERE username = %s", (username,))
            user = cur.fetchone()
            return {'id': user[0], 'username': user[1], 'password': user[2], 'role': user[3]} if user else None
    except psycopg2.Error as e:
        logger.error(f"Error fetching user: {e}")
        return None
    finally:
        conn.close()

def get_subjects_by_user(user_id: int) -> List[Subject]:
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT name, teacher, max_daily_slots, preferred_rooms
                FROM subjects
                WHERE created_by = %s
            """, (user_id,))
            subjects = cur.fetchall()
            return [Subject(name=s[0], teacher=s[1], max_daily_slots=s[2] or 2, preferred_rooms=s[3] or []) for s in subjects]
    except psycopg2.Error as e:
        logger.error(f"Error fetching subjects: {e}")
        return []
    finally:
        conn.close()

def get_timetables_by_user(user_id: int) -> List[dict]:
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT id, data, created_at FROM timetables
                WHERE created_by = %s AND NOT is_deleted
            """, (user_id,))
            timetables = cur.fetchall()
            logger.info(f"Retrieved {len(timetables)} timetables for user {user_id}")
            return [{
                'id': t[0],
                'data': t[1],
                'created_at': t[2].isoformat()
            } for t in timetables]
    except psycopg2.Error as e:
        logger.error(f"Error fetching timetables: {e}")
        return []
    finally:
        conn.close()

# API Routes
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    role = data.get('role')
    
    if not all([username, password, role]) or role not in ['teacher', 'admin']:
        logger.warning(f"Invalid registration data: {data}")
        return jsonify({'message': 'Invalid or missing fields'}), 400
    
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT 1 FROM users WHERE username = %s", (username,))
            if cur.fetchone():
                logger.warning(f"Username already exists: {username}")
                return jsonify({'message': 'Username already exists'}), 400
            
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            cur.execute(
                "INSERT INTO users (username, password, role) VALUES (%s, %s, %s) RETURNING id",
                (username, hashed_password, role)
            )
            user_id = cur.fetchone()[0]
            conn.commit()
            token = generate_token(user_id, role)
            logger.info(f"User registered: {username}")
            return jsonify({
                'message': 'Registration successful',
                'token': token,
                'user': {'id': user_id, 'username': username, 'role': role}
            }), 201
    except psycopg2.Error as e:
        conn.rollback()
        logger.error(f"Registration failed: {e}")
        return jsonify({'message': 'Database error'}), 500
    finally:
        conn.close()

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        logger.warning("Missing login credentials")
        return jsonify({'message': 'Missing username or password'}), 400
    
    user = get_user_by_username(username)
    if user and bcrypt.check_password_hash(user['password'], password):
        token = generate_token(user['id'], user['role'])
        logger.info(f"User logged in: {username}")
        return jsonify({
            'message': 'Login successful',
            'token': token,
            'user': {'id': user['id'], 'username': user['username'], 'role': user['role']}
        }), 200
    logger.warning(f"Invalid login attempt for: {username}")
    return jsonify({'message': 'Invalid credentials'}), 401

@app.route('/api/subjects', methods=['POST'])
@token_required
def create_subjects():
    user_id = request.user['user_id']
    role = request.user['role']
    
    if role not in ['teacher', 'admin']:
        logger.warning(f"Permission denied for user {user_id} with role {role}")
        return jsonify({'message': 'Permission denied'}), 403
    
    data = request.get_json()
    subjects = data.get('subjects', [])
    
    if not isinstance(subjects, list) or not all('name' in s and 'teacher' in s for s in subjects):
        logger.warning(f"Invalid subjects data: {data}")
        return jsonify({'message': 'Invalid subjects format'}), 400
    
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            for subject in subjects:
                name = subject['name']
                teacher = subject['teacher']
                max_daily_slots = subject.get('max_daily_slots', 2)
                preferred_rooms = subject.get('preferred_rooms', [])
                cur.execute("""
                    INSERT INTO subjects (name, teacher, max_daily_slots, preferred_rooms, created_by)
                    VALUES (%s, %s, %s, %s, %s)
                """, (name, teacher, max_daily_slots, preferred_rooms, user_id))
            conn.commit()
            logger.info(f"Subjects added for user {user_id}")
            return jsonify({'message': 'Subjects added successfully'}), 201
    except psycopg2.Error as e:
        conn.rollback()
        logger.error(f"Error adding subjects: {e}")
        return jsonify({'message': 'Database error'}), 500
    finally:
        conn.close()

@app.route('/api/timetables', methods=['GET'])
@token_required
def get_timetables():
    user_id = request.user['user_id']
    timetables = get_timetables_by_user(user_id)
    return jsonify(timetables), 200

@app.route('/api/timetables', methods=['POST'])
@token_required
def create_timetable():
    user_id = request.user['user_id']
    role = request.user['role']
    
    if role not in ['teacher', 'admin']:
        logger.warning(f"Permission denied for user {user_id} with role {role}")
        return jsonify({'message': 'Permission denied'}), 403
    
    subjects = get_subjects_by_user(user_id)
    if not subjects:
        logger.warning(f"No subjects found for user {user_id}")
        return jsonify({'message': 'No subjects defined. Add subjects first.'}), 400
    
    generator = TimetableGenerator(subjects)
    timetable_data = generator.generate()
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO timetables (data, created_by) VALUES (%s, %s) RETURNING id, created_at",
                (json.dumps(timetable_data), user_id)
            )
            timetable_id, created_at = cur.fetchone()
            conn.commit()
            file_path = os.path.join(EXPORT_DIR, f'timetable_{timetable_id}.json')
            with open(file_path, 'w') as f:
                json.dump(timetable_data, f, indent=2)
            logger.info(f"Timetable {timetable_id} created by user {user_id}")
            return jsonify({
                'id': timetable_id,
                'data': timetable_data,
                'created_at': created_at.isoformat()
            }), 201
    except psycopg2.Error as e:
        conn.rollback()
        logger.error(f"Error creating timetable: {e}")
        return jsonify({'message': 'Database error'}), 500
    finally:
        conn.close()

@app.route('/api/timetables/<int:id>', methods=['GET'])
@token_required
def get_timetable(id):
    user_id = request.user['user_id']
    role = request.user['role']
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id, data, created_at, created_by, is_deleted FROM timetables WHERE id = %s", (id,))
            timetable = cur.fetchone()
            if not timetable:
                logger.warning(f"Timetable {id} not found")
                return jsonify({'message': 'Timetable not found'}), 404
            if timetable[3] != user_id and role != 'admin' and not timetable[4]:
                logger.warning(f"Permission denied for user {user_id} on timetable {id}")
                return jsonify({'message': 'Permission denied'}), 403
            logger.info(f"Timetable {id} retrieved for user {user_id}")
            return jsonify({
                'id': timetable[0],
                'data': timetable[1],
                'created_at': timetable[2].isoformat()
            }), 200
    except psycopg2.Error as e:
        logger.error(f"Error fetching timetable {id}: {e}")
        return jsonify({'message': 'Database error'}), 500
    finally:
        conn.close()

@app.route('/api/timetables/<int:id>', methods=['DELETE'])
@token_required
def delete_timetable(id):
    user_id = request.user['user_id']
    role = request.user['role']
    
    if role not in ['teacher', 'admin']:
        logger.warning(f"Permission denied for user {user_id} with role {role}")
        return jsonify({'message': 'Permission denied'}), 403
    
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT created_by FROM timetables WHERE id = %s", (id,))
            timetable = cur.fetchone()
            if not timetable:
                logger.warning(f"Timetable {id} not found")
                return jsonify({'message': 'Timetable not found'}), 404
            if timetable[0] != user_id and role != 'admin':
                logger.warning(f"Permission denied for user {user_id} on timetable {id}")
                return jsonify({'message': 'Permission denied'}), 403
            cur.execute("UPDATE timetables SET is_deleted = TRUE WHERE id = %s", (id,))
            conn.commit()
            logger.info(f"Timetable {id} deleted by user {user_id}")
            return jsonify({'message': 'Timetable deleted successfully'}), 200
    except psycopg2.Error as e:
        conn.rollback()
        logger.error(f"Error deleting timetable {id}: {e}")
        return jsonify({'message': 'Database error'}), 500
    finally:
        conn.close()

@app.route('/api/timetables/<int:id>/export', methods=['GET'])
@token_required
def export_timetable(id):
    user_id = request.user['user_id']
    role = request.user['role']
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id, data, created_by, is_deleted FROM timetables WHERE id = %s", (id,))
            timetable = cur.fetchone()
            if not timetable:
                logger.warning(f"Timetable {id} not found for export")
                return jsonify({'message': 'Timetable not found'}), 404
            if timetable[2] != user_id and role != 'admin' and timetable[3]:
                logger.warning(f"Permission denied for user {user_id} on timetable {id}")
                return jsonify({'message': 'Permission denied'}), 403
            file_path = os.path.join(EXPORT_DIR, f'timetable_{id}.json')
            if not os.path.exists(file_path):
                with open(file_path, 'w') as f:
                    json.dump(timetable[1], f, indent=2)
            logger.info(f"Timetable {id} exported for user {user_id}")
            return send_file(file_path, as_attachment=True, download_name=f'timetable_{id}.json')
    except psycopg2.Error as e:
        logger.error(f"Error exporting timetable {id}: {e}")
        return jsonify({'message': 'Database error'}), 500
    finally:
        conn.close()

@app.route('/')
def serve_frontend():
    return send_from_directory('static', 'index.html')

@app.route('/favicon.ico')
def serve_favicon():
    return send_from_directory('static', 'favicon.ico')

if __name__ == '__main__':
    logger.info("Starting Flask application...")
    try:
        init_db()
        app.run(debug=True, host='0.0.0.0', port=5000)
        logger.info("Application running on http://0.0.0.0:5000")
    except Exception as e:
        logger.error(f"Failed to start application: {e}")
        raise