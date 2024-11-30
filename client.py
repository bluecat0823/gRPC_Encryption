import grpc
import password_manager_pb2
import password_manager_pb2_grpc

def run():
    with grpc.insecure_channel('localhost:50051') as channel:
        stub = password_manager_pb2_grpc.PasswordManagerStub(channel)

        while True:
            print("\nPassword Manager Client")
            print("1. Store Password")
            print("2. Retrieve Password")
            print("3. List Accounts")
            print("4. Delete Account")
            print("5. Exit")
            choice = input("Select an option: ")

            if choice == "1":
                # Store Password
                account = input("Enter account name: ")
                password = input("Enter password: ")
                response = stub.StorePassword(password_manager_pb2.PasswordRequest(account=account, password=password))
                print(response.status)

            elif choice == "2":
                # Retrieve Password
                account = input("Enter account name to retrieve password: ")
                response = stub.RetrievePassword(password_manager_pb2.AccountRequest(account=account))
                if response.password:
                    print(f"Account: {response.account}, Password: {response.password}")
                else:
                    print(response.status)

            elif choice == "3":
                # List Accounts
                response = stub.ListAccounts(password_manager_pb2.Empty())
                print("Accounts:", ", ".join(response.accounts) if response.accounts else "No accounts found.")

            elif choice == "4":
                # Delete Account
                account = input("Enter account name to delete: ")
                response = stub.DeletePassword(password_manager_pb2.AccountRequest(account=account))
                print(response.status)

            elif choice == "5":
                print("Exiting...")
                break

            else:
                print("Invalid option. Please try again.")

if __name__ == "__main__":
    run()
