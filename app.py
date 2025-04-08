from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__)

# Konfiguration für JWT und die MySQL-Datenbank
app.config['JWT_SECRET_KEY'] = 'weilisso001'  # Ersetze diesen Schlüssel durch einen sicheren Wert
# Beispiel einer MySQL-Konfiguration (Passe username, password, host und db nach Bedarf an)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://api_user:weilisso001@85.215.238.89:3306/api_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialisiere SQLAlchemy und JWTManager
db = SQLAlchemy(app)
jwt = JWTManager(app)

# -----------------------------------------------------------
# Datenbankmodelle
# -----------------------------------------------------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='user')

class Server(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    ip = db.Column(db.String(100), nullable=False)
    port = db.Column(db.Integer, nullable=False)
    location = db.Column(db.String(100), nullable=False)
    status = db.Column(db.String(20), nullable=False)

# -----------------------------------------------------------
# Authentifizierungs-Endpunkte
# Öffentliche Registrierung ist deaktiviert – neue Nutzer werden nur über /create_user
# erstellt, was nur Administratoren erlaubt.
# -----------------------------------------------------------

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({'msg': 'Username and password required'}), 400

    user = User.query.filter_by(username=username).first()
    if not user or not check_password_hash(user.password, password):
        return jsonify({'msg': 'Bad username or password'}), 401

    # Sende den Benutzernamen als Identität und füge die Rolle über additional_claims hinzu.
    access_token = create_access_token(identity=username, additional_claims={"role": user.role})
    return jsonify(access_token=access_token), 200

# Endpunkt zum Erstellen eines neuen Users; nur Admins dürfen diesen nutzen.
@app.route('/create_user', methods=['POST'])
@jwt_required()
def create_user():
    jwt_data = get_jwt()
    if jwt_data.get("role") != "superuser":
        return jsonify({"msg": "Unauthorized: Only superuser can create new users"}), 403

    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    if not username or not password:
        return jsonify({"msg": "Username and password required"}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({"msg": "User already exists"}), 400

    hashed_password = generate_password_hash(password)
    new_user = User(username=username, password=hashed_password, role='user')
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"msg": "User created successfully"}), 201

# Endpunkt zum Löschen eines Nutzers; nur Admins dürfen dies durchführen.
@app.route('/delete_user/<string:username>', methods=['DELETE'])
@jwt_required()
def delete_user(username):
    jwt_data = get_jwt()
    if jwt_data.get("role") != "superuser":
        return jsonify({"msg": "Unauthorized: Only superuser can delete users"}), 403

    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({"msg": "User not found"}), 404

    db.session.delete(user)
    db.session.commit()
    return jsonify({"msg": "User deleted successfully"}), 200

# -----------------------------------------------------------
# Endpunkte für die VPN-Serververwaltung
# -----------------------------------------------------------

@app.route('/servers', methods=['GET'])
def get_servers():
    servers = Server.query.all()
    servers_list = []
    for s in servers:
        servers_list.append({
            "id": s.id,
            "name": s.name,
            "ip": s.ip,
            "port": s.port,
            "location": s.location,
            "status": s.status
        })
    return jsonify(servers_list)

@app.route('/servers', methods=['POST'])
@jwt_required()
def add_server():
    data = request.get_json()
    # Überprüfe, ob alle erforderlichen Daten vorhanden sind
    if not all([data.get("name"), data.get("ip"), data.get("port"), data.get("location"), data.get("status")]):
        return jsonify({"msg": "Missing data for server"}), 400
    
    new_server = Server(
        name = data["name"],
        ip = data["ip"],
        port = data["port"],
        location = data["location"],
        status = data["status"]
    )
    db.session.add(new_server)
    db.session.commit()
    return jsonify({
        "id": new_server.id,
        "name": new_server.name,
        "ip": new_server.ip,
        "port": new_server.port,
        "location": new_server.location,
        "status": new_server.status
    }), 201

@app.route('/servers/<int:server_id>', methods=['PUT'])
@jwt_required()
def update_server(server_id):
    data = request.get_json()
    server = Server.query.get(server_id)
    if not server:
        return jsonify({"error": "Server not found"}), 404

    server.name = data.get("name", server.name)
    server.ip = data.get("ip", server.ip)
    server.port = data.get("port", server.port)
    server.location = data.get("location", server.location)
    server.status = data.get("status", server.status)
    db.session.commit()

    return jsonify({
        "id": server.id,
        "name": server.name,
        "ip": server.ip,
        "port": server.port,
        "location": server.location,
        "status": server.status
    })

@app.route('/servers/<int:server_id>', methods=['DELETE'])
@jwt_required()
def delete_server(server_id):
    server = Server.query.get(server_id)
    if not server:
        return jsonify({"error": "Server not found"}), 404

    db.session.delete(server)
    db.session.commit()
    return jsonify({"message": "Server deleted."})

# -----------------------------------------------------------
# Anwendung starten
# -----------------------------------------------------------
if __name__ == '__main__':
    # Erstelle die Tabellen, falls diese noch nicht existieren
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=5000)
