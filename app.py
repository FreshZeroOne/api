from flask import Flask, jsonify, request
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
import json

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = 'dein-sicherer-schluessel-hier'  # Ersetze diesen Schlüssel durch einen sicheren Wert
jwt = JWTManager(app)

# Hilfsfunktionen zum Laden und Speichern der Serverdaten aus der JSON-Datei
def load_server_data():
    with open('servers.json', 'r') as f:
        data = json.load(f)
    return data

def save_server_data(data):
    with open('servers.json', 'w') as f:
        json.dump(data, f, indent=4)

# Hilfsfunktionen zum Laden und Speichern der Benutzerdaten aus einer separaten Datei
def load_users():
    try:
        with open('users.json', 'r') as f:
            data = json.load(f)
    except FileNotFoundError:
        data = []
    return data

def save_users(data):
    with open('users.json', 'w') as f:
        json.dump(data, f, indent=4)

# --------------------------------------------------------------------
# Authentifizierungs-Endpunkte
# Öffentliche Registrierung ist deaktiviert – neue Nutzer werden nur über /create_user erstellt,
# was nur Administratoren erlaubt ist.
# --------------------------------------------------------------------

# Login: Bei korrekten Anmeldedaten wird ein JWT-Token zurückgegeben, der den Benutzernamen als Identität
# und die Rolle im additional_claim "role" enthält.
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username', None)
    password = data.get('password', None)
    if not username or not password:
        return jsonify({'msg': 'Username and password required'}), 400

    users = load_users()
    user = next((u for u in users if u['username'] == username), None)
    if not user or not check_password_hash(user['password'], password):
        return jsonify({'msg': 'Bad username or password'}), 401

    access_token = create_access_token(identity=username, additional_claims={"role": user.get("role", "user")})
    return jsonify(access_token=access_token), 200

# Geschützter Endpunkt: Neuer Benutzer anlegen – nur für Admins.
@app.route('/create_user', methods=['POST'])
@jwt_required()
def create_user():
    jwt_data = get_jwt()  # Erhalte alle JWT-Claims
    if jwt_data.get("role") != "superuser":
        return jsonify({"msg": "Unauthorized: Only superuser can create new users"}), 403

    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    if not username or not password:
        return jsonify({"msg": "Username and password required"}), 400

    users = load_users()
    if any(u["username"] == username for u in users):
        return jsonify({"msg": "User already exists"}), 400

    hashed_password = generate_password_hash(password)
    new_user = {"username": username, "password": hashed_password, "role": "user"}
    users.append(new_user)
    save_users(users)
    return jsonify({"msg": "User created successfully"}), 201

# Geschützter Endpunkt: Benutzer löschen – nur für Admins.
@app.route('/delete_user/<string:username>', methods=['DELETE'])
@jwt_required()
def delete_user(username):
    jwt_data = get_jwt()
    if jwt_data.get("role") != "superuser":
        return jsonify({"msg": "Unauthorized: Only superuser can delete users"}), 403

    users = load_users()
    new_users = [u for u in users if u["username"] != username]

    if len(new_users) == len(users):
        return jsonify({"msg": "User not found"}), 404

    save_users(new_users)
    return jsonify({"msg": "User deleted successfully"}), 200

# --------------------------------------------------------------------
# Endpunkte für die VPN-Serververwaltung
# --------------------------------------------------------------------

# Öffentlicher Endpunkt: Liefert die Liste der VPN-Server.
@app.route('/servers', methods=['GET'])
def get_servers():
    servers = load_server_data()
    return jsonify(servers)

# Geschützter Endpunkt: Neuer Server hinzufügen (nur für authentifizierte Nutzer).
@app.route('/servers', methods=['POST'])
@jwt_required()
def add_server():
    new_server = request.get_json()
    servers = load_server_data()

    new_id = max([s["id"] for s in servers], default=0) + 1
    new_server["id"] = new_id
    servers.append(new_server)

    save_server_data(servers)
    return jsonify(new_server), 201

# Geschützter Endpunkt: Vorhandenen Server aktualisieren.
@app.route('/servers/<int:server_id>', methods=['PUT'])
@jwt_required()
def update_server(server_id):
    updated_data = request.get_json()
    servers = load_server_data()
    updated_server = None

    for s in servers:
        if s["id"] == server_id:
            s.update(updated_data)
            updated_server = s
            break

    if updated_server:
        save_server_data(servers)
        return jsonify(updated_server)
    else:
        return jsonify({"error": "Server not found"}), 404

# Geschützter Endpunkt: Einen Server löschen.
@app.route('/servers/<int:server_id>', methods=['DELETE'])
@jwt_required()
def delete_server(server_id):
    servers = load_server_data()
    new_servers = [s for s in servers if s["id"] != server_id]

    if len(new_servers) == len(servers):
        return jsonify({"error": "Server not found"}), 404

    save_server_data(new_servers)
    return jsonify({"message": "Server deleted."})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
