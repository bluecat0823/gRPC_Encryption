from concurrent import futures
import grpc
import encryption_pb2
import encryption_pb2_grpc
import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import base64
from datetime import datetime

# 키 관리 저장소
KEY_STORE = {}

# 키 생성/로드 함수
def generate_or_load_keys(private_key_path, public_key_path):
    if os.path.exists(private_key_path) and os.path.exists(public_key_path):
        with open(private_key_path, "rb") as priv_file, open(public_key_path, "rb") as pub_file:
            private_key = rsa.PrivateKey.load_pkcs1(priv_file.read())
            public_key = rsa.PublicKey.load_pkcs1(pub_file.read())
    else:
        private_key, public_key = rsa.newkeys(2048)
        with open(private_key_path, "wb") as priv_file, open(public_key_path, "wb") as pub_file:
            priv_file.write(private_key.save_pkcs1())
            pub_file.write(public_key.save_pkcs1())
    return private_key, public_key

# 로그 기록 함수
def log_key_reset():
    os.makedirs("keys", exist_ok=True)
    with open("keys/key_reset.log", "a") as log_file:
        log_file.write(f"Keys reset at {datetime.now()}\n")

class EncryptionServiceServicer(encryption_pb2_grpc.EncryptionServiceServicer):
    def __init__(self):
        os.makedirs("keys", exist_ok=True)
        private_key_path = "keys/server_private.pem"
        public_key_path = "keys/server_public.pem"
        self.server_private_key, self.server_public_key = generate_or_load_keys(
            private_key_path, public_key_path
        )
        self.admin_token = "secure_admin_token"  # 관리자 인증 토큰

    def _generate_symmetric_key(self):
        return os.urandom(32)  # AES 256-bit key

    def _encrypt_with_aes(self, key, plaintext):
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
        encryptor = cipher.encryptor()
        encrypted = encryptor.update(plaintext.encode()) + encryptor.finalize()
        return base64.b64encode(iv + encrypted).decode()

    def _decrypt_with_aes(self, key, encrypted_data):
        data = base64.b64decode(encrypted_data)
        iv, encrypted = data[:16], data[16:]
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
        decryptor = cipher.decryptor()
        return decryptor.update(encrypted) + decryptor.finalize()

    def ExchangeKey(self, request, context):
        try:
            client_public_key = rsa.PublicKey.load_pkcs1(request.client_public_key.encode('utf-8'))
            symmetric_key = self._generate_symmetric_key()

            encrypted_symmetric_key = rsa.encrypt(symmetric_key, client_public_key)
            KEY_STORE[context.peer()] = symmetric_key

            return encryption_pb2.KeyExchangeResponse(
                encrypted_symmetric_key=base64.b64encode(encrypted_symmetric_key).decode('utf-8')
            )
        except Exception as e:
            context.abort(grpc.StatusCode.UNKNOWN, f"Key exchange failed: {e}")


    def EncryptMessage(self, request, context):
        symmetric_key = KEY_STORE.get(context.peer())
        if not symmetric_key:
            context.abort(grpc.StatusCode.UNAUTHENTICATED, "Key not found for peer.")
        encrypted_message = self._encrypt_with_aes(symmetric_key, request.plaintext)
        return encryption_pb2.EncryptResponse(encrypted_message=encrypted_message)

    def DecryptMessage(self, request, context):
        symmetric_key = KEY_STORE.get(context.peer())
        if not symmetric_key:
            context.abort(grpc.StatusCode.UNAUTHENTICATED, "Key not found for peer.")
        try:
            plaintext = self._decrypt_with_aes(symmetric_key, request.encrypted_message)
            return encryption_pb2.DecryptResponse(plaintext=plaintext.decode())
        except Exception as e:
            context.abort(grpc.StatusCode.INVALID_ARGUMENT, "Decryption failed.")

    def RegenerateKey(self, request, context):
        client_public_key = rsa.PublicKey.load_pkcs1(request.client_public_key.encode())
        symmetric_key = self._generate_symmetric_key()
        encrypted_symmetric_key = rsa.encrypt(symmetric_key, client_public_key)
        KEY_STORE[context.peer()] = symmetric_key
        return encryption_pb2.KeyExchangeResponse(
            encrypted_symmetric_key=base64.b64encode(encrypted_symmetric_key).decode()
        )

    def ResetKeys(self, request, context):
        if request.admin_token != self.admin_token:
            context.abort(grpc.StatusCode.PERMISSION_DENIED, "Unauthorized access.")
        try:
            private_key_path = "keys/server_private.pem"
            public_key_path = "keys/server_public.pem"
            os.remove(private_key_path)
            os.remove(public_key_path)
            self.server_private_key, self.server_public_key = generate_or_load_keys(
                private_key_path, public_key_path
            )
            KEY_STORE.clear()
            log_key_reset()
            return encryption_pb2.ResetKeysResponse(
                success=True, message="Keys have been successfully reset."
            )
        except Exception as e:
            return encryption_pb2.ResetKeysResponse(
                success=False, message=f"Failed to reset keys: {str(e)}"
            )


def serve():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    encryption_pb2_grpc.add_EncryptionServiceServicer_to_server(EncryptionServiceServicer(), server)
    server.add_insecure_port("[::]:50051")
    print("Server started at [::]:50051")
    server.start()
    server.wait_for_termination()


if __name__ == "__main__":
    serve()
