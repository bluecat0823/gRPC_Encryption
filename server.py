import grpc
import base64
import os
import rsa
from concurrent import futures
import encryption_pb2
import encryption_pb2_grpc

class EncryptionService(encryption_pb2_grpc.EncryptionServiceServicer):
    def __init__(self):
        self.private_key, self.public_key = rsa.newkeys(2048)

    def ExchangeKey(self, request, context):
        print(f"Received Public Key:\n{request.client_public_key}")
        try:
            client_public_key = rsa.PublicKey.load_pkcs1(request.client_public_key.encode('utf-8'))
            symmetric_key = os.urandom(32)
            encrypted_key = rsa.encrypt(symmetric_key, client_public_key)
            print(f"Generated Symmetric Key: {symmetric_key}")
            return encryption_pb2.KeyExchangeResponse(
                encrypted_symmetric_key=base64.b64encode(encrypted_key).decode('utf-8')
            )
        except ValueError as e:
            context.set_details(f"Key exchange failed: {str(e)}")
            context.set_code(grpc.StatusCode.UNKNOWN)
            return encryption_pb2.KeyExchangeResponse()

def serve():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    encryption_pb2_grpc.add_EncryptionServiceServicer_to_server(EncryptionService(), server)
    server.add_insecure_port('[::]:50051')
    print("Server started at [::]:50051")
    server.start()
    server.wait_for_termination()

if __name__ == "__main__":
    serve()

