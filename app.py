from flask import Flask, jsonify, request, redirect, url_for, render_template
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Column, Integer, String, Text, Boolean, DateTime
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, get_jwt
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS
import srp
import os
import json
import uuid
import base64
from cryptography.fernet import Fernet
from datetime import datetime, timezone, timedelta
import re
import paramiko
from io import StringIO
from pythonping import ping
from flask_migrate import Migrate
from dotenv import load_dotenv
import atexit
from apscheduler.schedulers.background import BackgroundScheduler
import pyotp
import logging

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)

# Configuration
app.config['SECRET_KEY'] = 'ein_sehr_geheimer_key_123456'
app.config['JWT_SECRET_KEY'] = 'weilisso001'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://api_user:weilisso001@85.215.238.89:3306/api_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
db = SQLAlchemy(app)
jwt = JWTManager(app)
login_manager = LoginManager(app)
login_manager.login_view = 'admin_login'

# Rate limiting configuration
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Error codes
ERROR_CODES = {
    'INVALID_REQUEST': 2000,
    'AUTHENTICATION_FAILED': 2001,
    'SESSION_NOT_FOUND': 2002,
    'INVALID_2FA': 2003,
    'SERVER_ERROR': 5000
}

# Session storage
sessions = {}
refresh_tokens = {}

# ------------------------------
# Database Models
# ------------------------------
class User(db.Model, UserMixin):
    __tablename__ = 'user'
    
    id = Column(Integer, primary_key=True)
    username = Column(String(80), unique=True, nullable=False)
    password = Column(String(200), nullable=False)
    role = Column(String(20), nullable=False, default='user')
    
    def __repr__(self):
        return f'<User {self.username}>'

class Server(db.Model):
    __tablename__ = 'server'
    
    id = Column(Integer, primary_key=True)
    name = Column(String(100), nullable=False)
    ip = Column(String(100), nullable=False)
    port = Column(Integer, nullable=False)
    location = Column(String(100), nullable=False)
    status = Column(String(20), nullable=False)
    ssh_private_key = Column(Text, nullable=True)

    def __repr__(self):
        return f'<Server {self.name}>'

class VPNUser(db.Model):
    __tablename__ = 'vpn_user'
    
    id = Column(Integer, primary_key=True)
    username = Column(String(80), unique=True, nullable=False)
    salt = Column(String(128), nullable=False)
    verifier = Column(String(512), nullable=False)
    two_factor_enabled = Column(Boolean, default=False)
    two_factor_secret = Column(String(32))
    two_factor_u2f = Column(Text)
    two_factor_totp = Column(Text)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        return {
            "UserId": str(self.id),
            "Username": self.username,
            "TwoFactor": {
                "Enabled": 1 if self.two_factor_enabled else 0,
                "U2F": json.loads(self.two_factor_u2f) if self.two_factor_u2f else [],
                "TOTP": json.loads(self.two_factor_totp) if self.two_factor_totp else []
            }
        }

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- Flask-Migrate Setup ---
migrate = Migrate(app, db)

# --- cryptography-Setup ---
load_dotenv()  # Lädt die Variablen aus der .env-Datei in os.environ

ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY")
if not ENCRYPTION_KEY:
    raise Exception("ENCRYPTION_KEY ist nicht gesetzt!")
fernet = Fernet(ENCRYPTION_KEY)

# --- Helper-Funktion für die Servermetriken ---
def reformat_pem(key_str):
    if "\n" in key_str:
        return key_str
    header = "-----BEGIN RSA PRIVATE KEY-----"
    footer = "-----END RSA PRIVATE KEY-----"
    content = key_str.replace(header, "").replace(footer, "").strip()
    lines = [content[i:i+64] for i in range(0, len(content), 64)]
    return header + "\n" + "\n".join(lines) + "\n" + footer + "\n"

def get_vpn_server_metrics(server, ssh_port=22, ssh_user='vpnmonitor'):
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        encrypted_key = server.ssh_private_key
        if not encrypted_key:
            raise Exception("Kein gültiger SSH-Key in der Datenbank gefunden.")
        
        key_data = fernet.decrypt(encrypted_key.encode('utf-8')).decode('utf-8')
        key_data = reformat_pem(key_data)

        key_file = StringIO(key_data)
        private_key = paramiko.RSAKey.from_private_key(key_file)
        
        client.connect(server.ip, port=ssh_port, username=ssh_user, pkey=private_key, timeout=5, allow_agent=False)
        
        stdin, stdout, stderr = client.exec_command("sudo wg show wg0 latest-handshakes", get_pty=True)
        handshake_output = stdout.read().decode("utf-8")
        active_peers = len([line for line in handshake_output.splitlines() if line.strip()])
        
        stdin, stdout, stderr = client.exec_command("uptime", get_pty=True)
        uptime_output = stdout.read().decode("utf-8").strip()
        running_match = re.search(r"up ([^,]+,[^,]+),", uptime_output)
        running_time = running_match.group(1).strip() if running_match else uptime_output
        
        user_match = re.search(r",\s*(\d+)\s+user[s]?", uptime_output)
        user_count = int(user_match.group(1)) if user_match else 0
        
        stdin, stdout, stderr = client.exec_command("free -m", get_pty=True)
        free_output = stdout.read().decode("utf-8")
        mem_line = next((line for line in free_output.splitlines() if line.startswith("Mem:")), None)
        if mem_line:
            parts = mem_line.split()
            ram_total, ram_used, ram_free = parts[1], parts[2], parts[3]
        else:
            ram_total = ram_used = ram_free = "n/a"
        
        stdin, stdout, stderr = client.exec_command("top -bn1 | grep 'Cpu(s)'", get_pty=True)
        cpu_output = stdout.read().decode("utf-8").strip()
        match_cpu = re.search(r"(\d+\.\d+)\s*%?\s*id", cpu_output)
        if match_cpu:
            idle = float(match_cpu.group(1))
            cpu_usage = round(100 - idle, 2)
        else:
            cpu_usage = "n/a"
        
        client.close()
        
        return {
            "active_peers": active_peers,
            "uptime": uptime_output,
            "running_time": running_time,
            "user_count": user_count,
            "ram_total": ram_total,
            "ram_used": ram_used,
            "ram_free": ram_free,
            "cpu_usage": cpu_usage
        }
    except Exception as e:
        print("Fehler in get_vpn_server_metrics:", e)
        return {
            "active_peers": 0,
            "uptime": str(e),
            "running_time": "n/a",
            "user_count": 0,
            "ram_total": "n/a",
            "ram_used": "n/a",
            "ram_free": "n/a",
            "cpu_usage": "n/a"
        }

def update_server_status():
    with app.app_context():
        servers = Server.query.all()
        for server in servers:
            try:
                response = ping(server.ip, count=1, timeout=2)
                if response.success():
                    if server.status != "online":
                        print(f"Server {server.name} ({server.ip}) is now online.")
                        server.status = "online"
                else:
                    if server.status != "offline":
                        print(f"Server {server.name} ({server.ip}) is now offline.")
                        server.status = "offline"
            except Exception as e:
                print(f"Fehler beim Pingen von {server.ip}: {e}")
                if server.status != "offline":
                    server.status = "offline"
        db.session.commit()

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password) and user.role in ['admin', 'superuser']:
            login_user(user)
            next_url = request.args.get('next')
            return redirect(next_url or url_for('dashboard'))
        else:
            return render_template('admin_login.html', error="Invalid credentials or unauthorized.")
    return render_template('admin_login.html')

@app.route('/admin/logout')
@login_required
def admin_logout():
    logout_user()
    return redirect(url_for('admin_login'))

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role not in ['admin', 'superuser']:
        return redirect(url_for('admin_login'))
    users = User.query.all()
    servers = Server.query.all()
    
    total_servers = len(servers)
    online_servers = sum(1 for s in servers if s.status == "online")
    
    total_peers = 0
    for server in servers:
        if server.status == "online":
            metrics = get_vpn_server_metrics(server, ssh_port=22, ssh_user='vpnmonitor')
            total_peers += metrics.get('active_peers', 0)
    
    return render_template("admin_dashboard.html",
                           users=users,
                           servers=servers,
                           total_servers=total_servers,
                           online_servers=online_servers,
                           total_peers=total_peers)

@app.route('/dashboard/benutzer')
@login_required
def dashboard_users():
    if current_user.role not in ['admin', 'superuser']:
        return redirect(url_for('admin_login'))
    page = request.args.get('page', 1, type=int)
    per_page = 10
    pagination = User.query.paginate(page=page, per_page=per_page, error_out=False)
    users = pagination.items
    return render_template('dashboard_users.html', users=users, pagination=pagination)

@app.route('/dashboard/server')
@login_required
def dashboard_servers():
    if current_user.role not in ['admin', 'superuser']:
        return redirect(url_for('admin_login'))
    page = request.args.get('page', 1, type=int)
    per_page = 10
    pagination = Server.query.paginate(page=page, per_page=per_page, error_out=False)
    servers = pagination.items

    server_cards = []
    for server in servers:
        metrics = get_vpn_server_metrics(server, ssh_port=22, ssh_user='vpnmonitor')
        card = {
            'id': server.id,
            'name': server.name,
            'ip': server.ip,
            'active_peers': metrics.get('active_peers'),
            'cpu_usage': metrics.get('cpu_usage'),
            'status': server.status
        }
        server_cards.append(card)

    return render_template('dashboard_servers.html', server_cards=server_cards, pagination=pagination)

@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    if current_user.role not in ['admin', 'superuser']:
        return redirect(url_for('admin_login'))
    
    if user_id == 0:
        user = None
    else:
        user = User.query.get_or_404(user_id)
    
    if request.method == 'POST':
        username = request.form.get('username')
        role = request.form.get('role')
        password = request.form.get('password')
        password_confirm = request.form.get('password_confirm')
        
        if user is None:
            if not username or not password or not password_confirm:
                error = "Username und beide Passwortfelder sind erforderlich."
                return render_template('edit_user.html', error=error, user=None)
            if password != password_confirm:
                error = "Die Passwörter stimmen nicht überein."
                return render_template('edit_user.html', error=error, user=None)
            new_user = User(username=username,
                            password=generate_password_hash(password),
                            role=role)
            db.session.add(new_user)
            db.session.commit()
        else:
            user.username = username
            user.role = role
            if password or password_confirm:
                if password != password_confirm:
                    error = "Die Passwörter stimmen nicht überein."
                    return render_template('edit_user.html', error=error, user=user)
                user.password = generate_password_hash(password)
            db.session.commit()
        return redirect(url_for('dashboard_users'))
    return render_template('edit_user.html', user=user)

@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if current_user.role not in ['admin', 'superuser']:
        return redirect(url_for('admin_login'))
    
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    return redirect(url_for('dashboard_users'))

@app.route('/edit_server/<int:server_id>', methods=['GET', 'POST'])
@login_required
def edit_server(server_id):
    if current_user.role not in ['admin', 'superuser']:
        return redirect(url_for('admin_login'))
        
    if server_id == 0:
        server = None
        metrics = None
    else:
        server = Server.query.get_or_404(server_id)
        metrics = get_vpn_server_metrics(server, ssh_port=22, ssh_user='vpnmonitor')
    
    if request.method == 'POST':
        name = request.form.get('name')
        ip = request.form.get('ip')
        port = request.form.get('port')
        location = request.form.get('location')
        status = request.form.get('status')
        key_input = request.form.get('ssh_private_key')

        if not (name and ip and port and location and status):
            error = "Alle Felder (außer SSH Private Key) müssen ausgefüllt sein."
            return render_template('edit_server.html', error=error, server=server, metrics=metrics)
        
        if key_input:
            encrypted_key = fernet.encrypt(key_input.encode('utf-8')).decode('utf-8')
        else:
            encrypted_key = None
        
        if server is None:
            new_server = Server(
                name=name,
                ip=ip,
                port=int(port),
                location=location,
                status=status,
                ssh_private_key=encrypted_key
            )
            db.session.add(new_server)
            db.session.commit()
        else:
            server.name = name
            server.ip = ip
            server.port = int(port)
            server.location = location
            server.status = status
            server.ssh_private_key = encrypted_key
            db.session.commit()
            
        return redirect(url_for('dashboard_servers'))
    
    return render_template('edit_server.html', server=server, metrics=metrics)

@app.route('/delete_server/<int:server_id>', methods=['POST'])
@login_required
def delete_server(server_id):
    if current_user.role not in ['admin', 'superuser']:
        return redirect(url_for('admin_login'))
    
    server = Server.query.get_or_404(server_id)
    db.session.delete(server)
    db.session.commit()
    return redirect(url_for('dashboard_servers'))

@app.route('/metrics/<int:server_id>')
@login_required
def server_metrics(server_id):
    if current_user.role not in ['admin', 'superuser']:
        return redirect(url_for('admin_login'))
    server = Server.query.get_or_404(server_id)
    if server.status != "online":
        return render_template('server_metrics.html', server=server, metrics={"error": "Server offline"})
    metrics = get_vpn_server_metrics(server, ssh_port=22, ssh_user='vpnmonitor')
    return render_template('server_metrics.html', server=server, metrics=metrics)

@app.route('/login', methods=['POST'])
def api_login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({'msg': 'Username and password required'}), 400
    user = User.query.filter_by(username=username).first()
    if not user or not check_password_hash(user.password, password):
        return jsonify({'msg': 'Bad username or password'}), 401
    access_token = create_access_token(identity=username, additional_claims={"role": user.role})
    return jsonify(access_token=access_token), 200

@app.route('/api/servers', methods=['GET'])
def get_servers():
    try:
        with open('servers.json', 'r') as file:
            return jsonify(json.load(file))
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/server-loads', methods=['GET'])
def get_server_loads():
    try:
        with open('server-loads.json', 'r') as file:
            return jsonify(json.load(file))
    except Exception as e:
        return jsonify({'error': str(e)}), 500

scheduler = BackgroundScheduler()
scheduler.add_job(func=update_server_status, trigger="interval", minutes=1)
scheduler.start()

atexit.register(lambda: scheduler.shutdown())

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        app.debug = True
    app.run(host='0.0.0.0', port=5000)