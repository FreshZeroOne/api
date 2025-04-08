from flask import Flask, jsonify
app = Flask(__name__)

# Beispielhafte Serverliste
servers = [
    {
        "id": 1,
        "name": "VPN-Server San Francisco",
        "ip": "64.227.101.26",
        "port": 51820,
        "location": "San Francisco, US",
        "status": "online"
    },
    {
        "id": 2,
        "name": "VPN-Server New York",
        "ip": "198.51.100.2",
        "port": 51820,
        "location": "New York, US",
        "status": "online"
    }
]

@app.route('/servers', methods=['GET'])
def get_servers():
    return jsonify(servers)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
