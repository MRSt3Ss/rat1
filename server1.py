import asyncio
import os
import logging
from aiohttp import ClientSession, ClientError

# --- Konfigurasi --- #
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - [SERVER-1-TCP] - %(levelname)s - %(message)s'
)

# Port ini akan digunakan oleh Railways TCP Proxy.
TCP_PORT = int(os.environ.get('PORT', 9999))

# URL internal server2.py. Ini WAJIB diatur di environment variable Railways nanti.
# Contoh: http://nama-service-server2.railway.internal:8080/agent/data
SERVER2_DATA_URL = os.environ.get('SERVER2_DATA_URL')

# --- Global State --- #
# Menyimpan koneksi aktif ke agent Android
AGENT_WRITER = None

# --- Logika Inti --- #

async def forward_data_to_server2(data: bytes, session: ClientSession):
    """Meneruskan data mentah dari agent ke server2 via HTTP POST."""
    if not SERVER2_DATA_URL:
        logging.warning("SERVER2_DATA_URL tidak diatur. Tidak bisa meneruskan data.")
        return

    try:
        # Kirim data mentah (bytes) di body request
        async with session.post(SERVER2_DATA_URL, data=data, timeout=5) as response:
            if response.status >= 300:
                logging.error(f"Gagal meneruskan data. Server2 merespon dengan status {response.status}")
            else:
                logging.info(f"Berhasil meneruskan {len(data)} bytes ke server2.")
                # Cek apakah server2 mengirim kembali perintah
                command = await response.text()
                if command and AGENT_WRITER:
                    logging.info(f"Menerima perintah dari server2: {command}")
                    AGENT_WRITER.write((command + '\n').encode('utf-8'))
                    await AGENT_WRITER.drain()

    except ClientError as e:
        logging.error(f"Gagal koneksi ke server2: {e}")
    except asyncio.TimeoutError:
        logging.error("Timeout saat meneruskan data ke server2.")

async def handle_agent(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    """Menangani siklus hidup koneksi dari agent Android."""
    global AGENT_WRITER
    if AGENT_WRITER:
        logging.warning("Agent baru mencoba konek, tapi sudah ada yang aktif. Koneksi baru ditutup.")
        writer.close()
        await writer.wait_closed()
        return

    AGENT_WRITER = writer
    addr = writer.get_extra_info('peername')
    logging.info(f"Agent Android terkoneksi dari {addr}")

    async with ClientSession() as session:
        # Beri tahu server2 bahwa agent telah terhubung
        await forward_data_to_server2(b'{"type": "status", "payload": "agent_connected"}', session)

        try:
            while True:
                data = await reader.read(16384)
                if not data:
                    logging.info("Agent menutup koneksi.")
                    break

                logging.info(f"Menerima {len(data)} bytes dari agent.")
                # Teruskan data mentah ke server2
                await forward_data_to_server2(data, session)

        except (ConnectionResetError, BrokenPipeError):
            logging.warning("Koneksi agent terputus tiba-tiba.")
        finally:
            logging.info("Membersihkan koneksi agent.")
            AGENT_WRITER = None
            writer.close()
            await writer.wait_closed()
            # Beri tahu server2 bahwa agent telah terputus
            async with ClientSession() as final_session:
                 await forward_data_to_server2(b'{"type": "status", "payload": "agent_disconnected"}', final_session)

async def main():
    """Memulai server TCP Gateway."""
    if not SERVER2_DATA_URL:
        logging.critical("KRITIS: Environment variable 'SERVER2_DATA_URL' belum diatur. Service ini tidak akan berfungsi. Keluar.")
        return

    server = await asyncio.start_server(handle_agent, '0.0.0.0', TCP_PORT)
    logging.info(f"TCP Gateway Server berjalan di port {TCP_PORT}")
    logging.info(f"Data akan diteruskan ke: {SERVER2_DATA_URL}")

    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logging.info("TCP Gateway Server berhenti.")
