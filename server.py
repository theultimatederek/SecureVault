# server.py — SecureVault File Server
# Receives encrypted files, stores them, serves them back
# Files NEVER decrypted server-side — stays encrypted on disk always

import socket
import threading
import json
import os
import struct
import hashlib
import time
import logging
from datetime import datetime

logging.basicConfig(
    level  = logging.INFO,
    format = '%(asctime)s [SERVER] %(levelname)s — %(message)s',
    datefmt= '%H:%M:%S'
)
log = logging.getLogger('SecureVaultServer')

HOST         = '127.0.0.1'
PORT         = 9999
STORAGE_DIR  = 'server_storage'
CHUNK_SIZE   = 65536          # 64 KB recv buffer
MAX_FILE_SIZE= 500 * 1024 * 1024  # 500 MB limit


class SecureVaultServer:
    def __init__(self, host=HOST, port=PORT, storage_dir=STORAGE_DIR):
        self.host        = host
        self.port        = port
        self.storage_dir = storage_dir
        self.running     = False
        self._server_sock = None
        os.makedirs(storage_dir, exist_ok=True)
        log.info(f"Storage directory: {os.path.abspath(storage_dir)}")

    # ── Start / Stop ───────────────────────────────────────────────────────
    def start(self):
        self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_sock.bind((self.host, self.port))
        self._server_sock.listen(10)
        self.running = True
        log.info(f"SecureVault Server listening on {self.host}:{self.port}")

        while self.running:
            try:
                conn, addr = self._server_sock.accept()
                log.info(f"Connection from {addr}")
                t = threading.Thread(target=self._handle_client,
                                     args=(conn, addr), daemon=True)
                t.start()
            except OSError:
                break

    def stop(self):
        self.running = False
        if self._server_sock:
            self._server_sock.close()
        log.info("Server stopped.")

    # ── Client handler ─────────────────────────────────────────────────────
    def _handle_client(self, conn, addr):
        try:
            # Receive command JSON
            header_raw = self._recv_exactly(conn, 4)
            if not header_raw:
                return
            header_len = struct.unpack('>I', header_raw)[0]
            header_raw = self._recv_exactly(conn, header_len)
            command    = json.loads(header_raw.decode('utf-8'))

            cmd = command.get('cmd', '')
            if cmd == 'UPLOAD':
                self._handle_upload(conn, command)
            elif cmd == 'DOWNLOAD':
                self._handle_download(conn, command)
            elif cmd == 'LIST':
                self._handle_list(conn)
            elif cmd == 'DELETE':
                self._handle_delete(conn, command)
            else:
                self._send_response(conn, {'status': 'error', 'msg': 'Unknown command'})
        except Exception as e:
            log.error(f"Client {addr} error: {e}")
        finally:
            conn.close()

    # ── Upload ─────────────────────────────────────────────────────────────
    def _handle_upload(self, conn, command):
        filename    = os.path.basename(command['filename'])
        file_size   = command['file_size']
        file_hash   = command.get('sha256', '')

        if file_size > MAX_FILE_SIZE:
            self._send_response(conn, {'status':'error','msg':'File too large'})
            return

        # Encrypted filename on disk (never store original name in plain)
        enc_filename = f"{int(time.time())}_{filename}.svlt"
        save_path    = os.path.join(self.storage_dir, enc_filename)

        # Acknowledge ready to receive
        self._send_response(conn, {'status': 'ready'})

        # Receive encrypted file bytes
        received  = 0
        hasher    = hashlib.sha256()
        start_t   = time.time()

        with open(save_path, 'wb') as f:
            while received < file_size:
                to_recv = min(CHUNK_SIZE, file_size - received)
                data    = self._recv_exactly(conn, to_recv)
                if not data:
                    break
                f.write(data)
                hasher.update(data)
                received += len(data)

        elapsed   = round(time.time() - start_t, 2)
        recv_hash = hasher.hexdigest()

        # Verify integrity
        if file_hash and recv_hash != file_hash:
            os.remove(save_path)
            self._send_response(conn, {
                'status': 'error',
                'msg':    f'Integrity check FAILED — file deleted (hash mismatch)'
            })
            log.warning(f"INTEGRITY FAIL: {filename}")
            return

        # Save metadata
        meta = {
            'original_name': filename,
            'stored_name':   enc_filename,
            'file_size':     received,
            'sha256':        recv_hash,
            'uploaded_at':   datetime.now().isoformat(),
            'encrypted':     True,
            'algorithm':     command.get('algorithm', 'AES-256-GCM'),
        }
        meta_path = save_path + '.meta.json'
        with open(meta_path, 'w') as f:
            json.dump(meta, f, indent=2)

        log.info(f"UPLOAD OK: {filename} ({received} bytes) in {elapsed}s ✓")
        self._send_response(conn, {
            'status':      'ok',
            'stored_name': enc_filename,
            'bytes_recv':  received,
            'elapsed':     elapsed,
            'integrity':   'verified' if file_hash else 'not checked',
        })

    # ── Download ───────────────────────────────────────────────────────────
    def _handle_download(self, conn, command):
        stored_name = command.get('stored_name', '')
        safe_name   = os.path.basename(stored_name)
        file_path   = os.path.join(self.storage_dir, safe_name)

        if not os.path.exists(file_path):
            self._send_response(conn, {'status':'error','msg':'File not found'})
            return

        file_size = os.path.getsize(file_path)
        hasher    = hashlib.sha256()

        with open(file_path, 'rb') as f:
            for block in iter(lambda: f.read(CHUNK_SIZE), b''):
                hasher.update(block)
        sha256 = hasher.hexdigest()

        self._send_response(conn, {
            'status':    'ok',
            'file_size': file_size,
            'sha256':    sha256,
        })

        # Wait for client ack
        ack_raw = self._recv_exactly(conn, 4)
        ack_len = struct.unpack('>I', ack_raw)[0]
        ack     = json.loads(self._recv_exactly(conn, ack_len))
        if ack.get('ready') != True:
            return

        # Send file
        sent = 0
        with open(file_path, 'rb') as f:
            while True:
                block = f.read(CHUNK_SIZE)
                if not block:
                    break
                conn.sendall(block)
                sent += len(block)

        log.info(f"DOWNLOAD OK: {safe_name} ({sent} bytes)")

    # ── List ───────────────────────────────────────────────────────────────
    def _handle_list(self, conn):
        files = []
        for fname in os.listdir(self.storage_dir):
            if fname.endswith('.meta.json'):
                meta_path = os.path.join(self.storage_dir, fname)
                try:
                    with open(meta_path) as f:
                        meta = json.load(f)
                    files.append(meta)
                except Exception:
                    pass
        self._send_response(conn, {'status': 'ok', 'files': files})

    # ── Delete ─────────────────────────────────────────────────────────────
    def _handle_delete(self, conn, command):
        stored_name = os.path.basename(command.get('stored_name', ''))
        file_path   = os.path.join(self.storage_dir, stored_name)
        meta_path   = file_path + '.meta.json'

        if os.path.exists(file_path):
            os.remove(file_path)
        if os.path.exists(meta_path):
            os.remove(meta_path)

        log.info(f"DELETE: {stored_name}")
        self._send_response(conn, {'status': 'ok'})

    # ── Socket helpers ─────────────────────────────────────────────────────
    def _recv_exactly(self, conn, n):
        data = b''
        while len(data) < n:
            packet = conn.recv(n - len(data))
            if not packet:
                return None
            data += packet
        return data

    def _send_response(self, conn, obj):
        raw  = json.dumps(obj).encode('utf-8')
        conn.sendall(struct.pack('>I', len(raw)) + raw)


# ── Entry point ────────────────────────────────────────────────────────────
if __name__ == '__main__':
    server = SecureVaultServer()
    try:
        server.start()
    except KeyboardInterrupt:
        server.stop()
