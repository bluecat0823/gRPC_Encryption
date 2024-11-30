import grpc
import password_manager_pb2
import password_manager_pb2_grpc

def run():
    with grpc.insecure_channel('localhost:50051') as channel:
        stub = password_manager_pb2_grpc.PasswordManagerStub(channel)

        # Store Password
        response = stub.StorePassword(password_manager_pb2.PasswordRequest(account="example", password="mypassword"))
        print(response.status)

        # Retrieve Password
        response = stub.RetrievePassword(password_manager_pb2.AccountRequest(account="example"))
        print(f"Account: {response.account}, Password: {response.password}")

        # List Accounts
        response = stub.ListAccounts(password_manager_pb2.Empty())
        print("Accounts:", response.accounts)

        # Delete Password
        response = stub.DeletePassword(password_manager_pb2.AccountRequest(account="example"))
        print(response.status)

if __name__ == "__main__":
    run()
