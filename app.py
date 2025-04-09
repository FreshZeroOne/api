from flask import Flask, jsonify, request, redirect, url_for, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
import os

app = Flask(__name__)

# Konfiguration
app.config['SECRET_KEY'] = 'ein_sehr_geheimer_key_123456'  # Langer, zufälliger String
app.config['JWT_SECRET_KEY'] = 'weilisso001'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://api_user:weilisso001@85.215.238.89:3306/api_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
jwt = JWTManager(app)

# Flask-Login Setup
login_manager = LoginManager(app)
login_manager.login_view = 'admin_login'

# ------------------------------
# Datenbankmodelle
# ------------------------------
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='user')
    
    def __repr__(self):
        return f'<User {self.username}>'

class Server(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    ip = db.Column(db.String(100), nullable=False)
    port = db.Column(db.Integer, nullable=False)
    location = db.Column(db.String(100), nullable=False)
    status = db.Column(db.String(20), nullable=False)
    
    def __repr__(self):
        return f'<Server {self.name}>'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ------------------------------
# Admin-Login Routen (Flask-Login)
# ------------------------------
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        # Nur Admins oder Superuser sind berechtigt
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

# ------------------------------
# Dashboard-Route (eigenes Template)
# ------------------------------
@app.route('/dashboard')
@login_required
def dashboard():
    # Prüfe, ob der Benutzer Adminrechte hat
    if current_user.role not in ['admin', 'superuser']:
        return redirect(url_for('admin_login'))
    users = User.query.all()
    servers = Server.query.all()
    return render_template('admin_dashboard.html', users=users, servers=servers)

# Route: Benutzerverwaltung – zeigt alle Benutzer in einem eigenen Template
@app.route('/dashboard/benutzer')
@login_required
def dashboard_users():
    if current_user.role not in ['admin', 'superuser']:
        return redirect(url_for('admin_login'))
    users = User.query.all()
    return render_template('dashboard_users.html', users=users)

# Route: Serververwaltung – zeigt alle Server in einem eigenen Template
@app.route('/dashboard/server')
@login_required
def dashboard_servers():
    if current_user.role not in ['admin', 'superuser']:
        return redirect(url_for('admin_login'))
    servers = Server.query.all()
    return render_template('dashboard_servers.html', servers=servers)

# ------------------------------
# Bearbeitungsrouten für Benutzer
# ------------------------------
@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    # Zugriff nur für Admins/Superuser
    if current_user.role not in ['admin', 'superuser']:
        return redirect(url_for('admin_login'))
    
    # Falls user_id = 0, behandeln wir es als Neuanlage
    if user_id == 0:
        user = None
    else:
        user = User.query.get_or_404(user_id)
    
    if request.method == 'POST':
        username = request.form.get('username')
        role = request.form.get('role')
        # Lese beide Passwortfelder
        password = request.form.get('password')
        password_confirm = request.form.get('password_confirm')
        
        # Falls ein neuer Benutzer angelegt wird:
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
            # Bestehenden Benutzer aktualisieren:
            user.username = username
            user.role = role
            # Falls Felder zur Passwortänderung ausgefüllt wurden:
            if password or password_confirm:
                if password != password_confirm:
                    error = "Die Passwörter stimmen nicht überein."
                    return render_template('edit_user.html', error=error, user=user)
                user.password = generate_password_hash(password)
            db.session.commit()
        return redirect(url_for('dashboard_users'))
    return render_template('edit_user.html', user=user)


# ------------------------------
# Löschen für Benutzer
# ------------------------------
@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    # Nur Admins oder Superuser dürfen löschen
    if current_user.role not in ['admin', 'superuser']:
        return redirect(url_for('admin_login'))
    
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    return redirect(url_for('dashboard_users'))

# ------------------------------
# Bearbeitungsrouten für Server
# ------------------------------
@app.route('/edit_server/<int:server_id>', methods=['GET', 'POST'])
@login_required
def edit_server(server_id):
    # Nur Admins oder Superuser dürfen bearbeiten oder anlegen
    if current_user.role not in ['admin', 'superuser']:
        return redirect(url_for('admin_login'))
        
    # Wenn server_id == 0, handelt es sich um eine Neuanlage
    if server_id == 0:
        server = None
    else:
        server = Server.query.get_or_404(server_id)
        
    if request.method == 'POST':
        name = request.form.get('name')
        ip = request.form.get('ip')
        port = request.form.get('port')
        location = request.form.get('location')
        status = request.form.get('status')
        
        # Überprüfe, ob alle Felder ausgefüllt sind
        if not (name and ip and port and location and status):
            error = "Alle Felder müssen ausgefüllt sein."
            return render_template('edit_server.html', error=error, server=server)
        
        if server is None:
            # Neuer Server
            new_server = Server(
                name=name,
                ip=ip,
                port=int(port),
                location=location,
                status=status
            )
            db.session.add(new_server)
            db.session.commit()
        else:
            # Bestehenden Server aktualisieren
            server.name = name
            server.ip = ip
            server.port = int(port)
            server.location = location
            server.status = status
            db.session.commit()
            
        return redirect(url_for('dashboard_servers'))
    
    return render_template('edit_server.html', server=server)

# ------------------------------
# Beispiel-API-Routen (JWT-geschützt) – falls nötig
# ------------------------------
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

# Weitere API-Routen können analog hinzugefügt werden.

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        app.debug = True  # Debugmodus aktivieren
    app.run(host='0.0.0.0', port=5000)
