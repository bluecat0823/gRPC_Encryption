from concurrent import futures
import grpc
import encryption_pb2
import encryption_pb2_grpc
import rsa
import base64
import os

KEY_STORE = {}

def generate_or_load_keys(private_key_path, public_key_path):
    if os.path.exists(private_key_path) and os.path.exists(public_key_path):
        with open(private_key_path, "rb") as priv_file, open(public_key_path, "rb") as pub_file:
            private_key = rsa.PrivateKey.load_pkcs1(priv_file.read())
            public_key = rsa.PublicKey.load_pkcs1(pub_file.read())
        print("Loaded existing keys:")
    else:
        private_key, public_key = rsa.newkeys(2048)
        with open(private_key_path, "wb") as priv_file, open(public_key_path, "wb") as pub_file:
            priv_file.write(private_key.save_pkcs1())
            pub_file.write(public_key.save_pkcs1())
        print("Generated new keys:")
    print(f"Private Key: {private_key.save_pkcs1(format='PEM').decode('utf-8')}")
    print(f"Public Key: {public_key.save_pkcs1(format='PEM').decode('utf-8')}")
    return private_key, public_key

class EncryptionServiceServicer(encryption_pb2_grpc.EncryptionServiceServicer):
    def __init__(self):
        os.makedirs("keys", exist_ok=True)
        private_key_path = "keys/server_private.pem"
        public_key_path = "keys/server_public.pem"
        self.server_private_key, self.server_public_key = generate_or_load_keys(
            private_key_path, public_key_path
        )

    def ExchangeKey(self, request, context):
        try:
            client_public_key = rsa.PublicKey.load_pkcs1(request.client_public_key.encode('utf-8'))
            print(f"Received Public Key:\n{request.client_public_key}")
            symmetric_key = os.urandom(32)
            encrypted_symmetric_key = rsa.encrypt(symmetric_key, client_public_key)
            KEY_STORE[context.peer()] = symmetric_key
            print(f"Symmetric Key for {context.peer()} set.")
            return encryption_pb2.KeyExchangeResponse(
                encrypted_symmetric_key=base64.b64encode(encrypted_symmetric_key).decode('utf-8')
            )
        except Exception as e:
            context.abort(grpc.StatusCode.UNKNOWN, f"Key exchange failed: {e}")

def serve():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    encryption_pb2_grpc.add_EncryptionServiceServicer_to_server(EncryptionServiceServicer(), server)
    server.add_insecure_port("[::]:50051")
    server.start()
    print("Server started at [::]:50051")
    server.wait_for_termination()

if __name__ == "__main__":
    serve()
