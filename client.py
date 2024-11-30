import grpc
import encryption_pb2
import encryption_pb2_grpc
import rsa
import base64
import os

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

class EncryptionClient:
    def __init__(self, server_address):
        self.channel = grpc.insecure_channel(server_address)
        self.stub = encryption_pb2_grpc.EncryptionServiceStub(self.channel)
        private_key_path = "keys/client_private.pem"
        public_key_path = "keys/client_public.pem"
        self.private_key, self.public_key = generate_or_load_keys(private_key_path, public_key_path)
        self.symmetric_key = None

    def exchange_key(self):
        response = self.stub.ExchangeKey(
            encryption_pb2.KeyExchangeRequest(
                client_public_key=self.public_key.save_pkcs1().decode()
            )
        )
        encrypted_key = base64.b64decode(response.encrypted_symmetric_key)
        self.symmetric_key = rsa.decrypt(encrypted_key, self.private_key)
        print("Symmetric key exchanged successfully!")

    def encrypt_message(self, message):
        response = self.stub.EncryptMessage(encryption_pb2.EncryptRequest(plaintext=message))
        print(f"Encrypted Message: {response.encrypted_message}")
        return response.encrypted_message

    def decrypt_message(self, encrypted_message):
        response = self.stub.DecryptMessage(
            encryption_pb2.DecryptRequest(encrypted_message=encrypted_message)
        )
        print(f"Decrypted Message: {response.plaintext}")
        return response.plaintext

    def regenerate_key(self):
        response = self.stub.RegenerateKey(
            encryption_pb2.KeyRegenerationRequest(
                client_public_key=self.public_key.save_pkcs1().decode()
            )
        )
        encrypted_key = base64.b64decode(response.encrypted_symmetric_key)
        self.symmetric_key = rsa.decrypt(encrypted_key, self.private_key)
        print("Symmetric key regenerated successfully!")

    def reset_keys(self, admin_token):
        response = self.stub.ResetKeys(
            encryption_pb2.ResetKeysRequest(admin_token=admin_token)
        )
        if response.success:
            print(f"Keys reset successfully: {response.message}")
            self.exchange_key()
        else:
            print(f"Failed to reset keys: {response.message}")


if __name__ == "__main__":
    client = EncryptionClient("localhost:50051")
    client.exchange_key()
    encrypted = client.encrypt_message("Hello, gRPC!")
    client.decrypt_message(encrypted)
    client.regenerate_key()
    client.reset_keys("secure_admin_token")
