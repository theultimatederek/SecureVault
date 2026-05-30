# client.py — SecureVault Client
# Encrypts files locally, transfers to server, decrypts on download

import socket
import struct
import json
import os
import hashlib
import time

from crypto_engine import (
    encrypt_file, decrypt_file,
    derive_key, generate_session_key,
    file_sha256, human_size,
    SALT_SIZE, FILE_MAGIC
)

HOST = '127.0.0.1'
PORT = 9999


class SecureVaultClient:
    def __init__(self, host=HOST, port=PORT, password='', callback=None):
        self.host     = host
        self.port     = port
        self.password = password
        self.callback = callback
        self._salt    = os.urandom(SALT_SIZE)
        self._key     = derive_key(password, self._salt) if password else generate_session_key()

    def log(self, msg, level='info'):
        if self.callback:
            self.callback(msg, level)
        else:
            print(f"[{level.upper()}] {msg}")

    # ── Connection helper ──────────────────────────────────────────────────
    def _connect(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(30)
        sock.connect((self.host, self.port))
        return sock

    def _send_command(self, sock, cmd_obj):
        raw  = json.dumps(cmd_obj).encode('utf-8')
        sock.sendall(struct.pack('>I', len(raw)) + raw)

    def _recv_response(self, sock):
        header = self._recv_exactly(sock, 4)
        length = struct.unpack('>I', header)[0]
        raw    = self._recv_exactly(sock, length)
        return json.loads(raw.decode('utf-8'))

    def _recv_exactly(self, sock, n):
        data = b''
        while len(data) < n:
            pkt = sock.recv(n - len(data))
            if not pkt:
                raise ConnectionError("Connection dropped")
            data += pkt
        return data

    # ── Upload ─────────────────────────────────────────────────────────────
    def upload(self, file_path: str, progress_cb=None) -> dict:
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        filename    = os.path.basename(file_path)
        file_size   = os.path.getsize(file_path)
        self.log(f"Encrypting {filename} ({human_size(file_size)})...", 'info')

        # Encrypt locally first
        enc_path = file_path + '.svlt'
        t0       = time.time()

        meta = encrypt_file(
            src_path    = file_path,
            dst_path    = enc_path,
            key         = self._key,
            progress_cb = progress_cb,
        )
        enc_time = round(time.time() - t0, 2)
        self.log(f"Encrypted in {enc_time}s → {human_size(meta['encrypted_size'])}", 'ok')

        # Compute SHA-256 of encrypted file for server-side integrity check
        enc_hash  = file_sha256(enc_path)
        enc_size  = os.path.getsize(enc_path)

        self.log(f"Uploading to {self.host}:{self.port}...", 'info')

        sock = self._connect()
        try:
            self._send_command(sock, {
                'cmd':       'UPLOAD',
                'filename':  filename + '.svlt',
                'file_size': enc_size,
                'sha256':    enc_hash,
                'algorithm': 'AES-256-GCM + HMAC-SHA256',
            })

            resp = self._recv_response(sock)
            if resp.get('status') != 'ready':
                raise RuntimeError(f"Server: {resp.get('msg','error')}")

            # Stream encrypted file to server
            t1   = time.time()
            sent = 0
            with open(enc_path, 'rb') as f:
                while True:
                    block = f.read(65536)
                    if not block:
                        break
                    sock.sendall(block)
                    sent += len(block)
                    if progress_cb:
                        progress_cb(sent, enc_size, 0)

            result = self._recv_response(sock)
            elapsed = round(time.time() - t1, 2)

            if result.get('status') == 'ok':
                self.log(f"Upload OK — {human_size(sent)} in {elapsed}s "
                         f"[integrity: {result.get('integrity','—')}]", 'ok')
            else:
                self.log(f"Upload FAILED: {result.get('msg')}", 'vuln')

            result['enc_path']    = enc_path
            result['original']    = file_path
            result['encrypt_time']= enc_time
            result['upload_time'] = elapsed
            return result

        finally:
            sock.close()
            # Clean up temp encrypted file
            if os.path.exists(enc_path):
                os.remove(enc_path)

    # ── Download ───────────────────────────────────────────────────────────
    def download(self, stored_name: str, save_dir: str = '.', progress_cb=None) -> dict:
        self.log(f"Requesting {stored_name} from server...", 'info')
        sock = self._connect()

        try:
            self._send_command(sock, {
                'cmd':         'DOWNLOAD',
                'stored_name': stored_name,
            })

            resp = self._recv_response(sock)
            if resp.get('status') != 'ok':
                raise RuntimeError(f"Server: {resp.get('msg','error')}")

            file_size  = resp['file_size']
            server_hash= resp.get('sha256', '')

            # Tell server we're ready
            self._send_command(sock, {'ready': True})

            # Receive encrypted file
            enc_path = os.path.join(save_dir, stored_name + '.tmp')
            received = 0
            hasher   = hashlib.sha256()
            t0       = time.time()

            with open(enc_path, 'wb') as f:
                while received < file_size:
                    to_recv = min(65536, file_size - received)
                    data    = self._recv_exactly(sock, to_recv)
                    f.write(data)
                    hasher.update(data)
                    received += len(data)
                    if progress_cb:
                        progress_cb(received, file_size, 0)

            elapsed = round(time.time() - t0, 2)

            # Verify integrity
            recv_hash = hasher.hexdigest()
            if server_hash and recv_hash != server_hash:
                os.remove(enc_path)
                raise RuntimeError("Integrity check FAILED — possible MITM attack!")

            self.log(f"Download OK — {human_size(received)} in {elapsed}s [integrity ✓]", 'ok')

            # Decrypt
            orig_name  = stored_name.replace('.svlt','').lstrip('0123456789_')
            dec_path   = os.path.join(save_dir, 'decrypted_' + orig_name)
            self.log(f"Decrypting to {dec_path}...", 'info')

            dec_meta = decrypt_file(enc_path, dec_path, self._key, progress_cb)
            os.remove(enc_path)

            self.log(f"Decrypted {dec_meta['chunks_verified']} chunks verified ✓", 'ok')
            return {
                'status':       'ok',
                'saved_to':     dec_path,
                'bytes':        received,
                'download_time':elapsed,
                'chunks':       dec_meta['chunks_verified'],
            }

        finally:
            sock.close()

    # ── List files ─────────────────────────────────────────────────────────
    def list_files(self) -> list:
        sock = self._connect()
        try:
            self._send_command(sock, {'cmd': 'LIST'})
            resp = self._recv_response(sock)
            return resp.get('files', [])
        finally:
            sock.close()

    # ── Delete ─────────────────────────────────────────────────────────────
    def delete_file(self, stored_name: str) -> dict:
        sock = self._connect()
        try:
            self._send_command(sock, {'cmd':'DELETE','stored_name':stored_name})
            return self._recv_response(sock)
        finally:
            sock.close()
