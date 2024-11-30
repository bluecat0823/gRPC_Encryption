import grpc
import base64
import os
import rsa
import encryption_pb2
import encryption_pb2_grpc

class EncryptionClient:
    def __init__(self, host='localhost', port=50051):
        self.channel = grpc.insecure_channel(f"{host}:{port}")
        self.stub = encryption_pb2_grpc.EncryptionServiceStub(self.channel)
        self.private_key, self.public_key = rsa.newkeys(2048)
        self.symmetric_key = None

    def exchange_key(self):
        # Send public key in PEM format
        public_key_pem = self.public_key.save_pkcs1(format='PEM').decode('utf-8')
        print(f"Sending Public Key:\n{public_key_pem}")
        try:
            response = self.stub.ExchangeKey(
                encryption_pb2.KeyExchangeRequest(client_public_key=public_key_pem)
            )
            encrypted_key = base64.b64decode(response.encrypted_symmetric_key)
            self.symmetric_key = rsa.decrypt(encrypted_key, self.private_key)
            print(f"Symmetric key established successfully: {self.symmetric_key}")
        except grpc.RpcError as e:
            print(f"Error during key exchange: {e.details()}")
            raise

    def encrypt_message(self, message):
        if self.symmetric_key is None:
            raise RuntimeError("Symmetric key not established. Call exchange_key first.")
        return base64.b64encode(message.encode('utf-8'))

    def decrypt_message(self, encrypted_message):
        if self.symmetric_key is None:
            raise RuntimeError("Symmetric key not established. Call exchange_key first.")
        return base64.b64decode(encrypted_message).decode('utf-8')


if __name__ == "__main__":
    client = EncryptionClient()
    try:
        client.exchange_key()
    except Exception as e:
        print(f"Failed to exchange keys: {e}")
