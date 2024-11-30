import grpc
from concurrent import futures
import sqlite3
from cryptography.fernet import Fernet
import password_manager_pb2
import password_manager_pb2_grpc

# AES Encryption Key
key = Fernet.generate_key()
cipher_suite = Fernet(key)

DATABASE = "passwords.db"

def init_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS passwords (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        account TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )
    """)
    conn.commit()
    conn.close()

class PasswordManagerServicer(password_manager_pb2_grpc.PasswordManagerServicer):
    def StorePassword(self, request, context):
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        encrypted_password = cipher_suite.encrypt(request.password.encode())
        try:
            cursor.execute("INSERT INTO passwords (account, password) VALUES (?, ?)", 
                           (request.account, encrypted_password))
            conn.commit()
            return password_manager_pb2.PasswordResponse(
                account=request.account, 
                password="", 
                status="Password stored successfully"
            )
        except sqlite3.IntegrityError:
            return password_manager_pb2.PasswordResponse(
                account=request.account, 
                password="", 
                status="Account already exists"
            )
        finally:
            conn.close()

    def RetrievePassword(self, request, context):
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute("SELECT password FROM passwords WHERE account=?", (request.account,))
        result = cursor.fetchone()
        conn.close()
        if result:
            decrypted_password = cipher_suite.decrypt(result[0]).decode()
            return password_manager_pb2.PasswordResponse(
                account=request.account, 
                password=decrypted_password, 
                status="Password retrieved successfully"
            )
        else:
            return password_manager_pb2.PasswordResponse(
                account=request.account, 
                password="", 
                status="Account not found"
            )

    def DeletePassword(self, request, context):
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM passwords WHERE account=?", (request.account,))
        conn.commit()
        rows_affected = cursor.rowcount
        conn.close()
        if rows_affected > 0:
            return password_manager_pb2.StatusResponse(status="Account deleted successfully")
        else:
            return password_manager_pb2.StatusResponse(status="Account not found")

    def ListAccounts(self, request, context):
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute("SELECT account FROM passwords")
        accounts = [row[0] for row in cursor.fetchall()]
        conn.close()
        return password_manager_pb2.AccountListResponse(accounts=accounts)

def serve():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    password_manager_pb2_grpc.add_PasswordManagerServicer_to_server(PasswordManagerServicer(), server)
    server.add_insecure_port('[::]:50051')
    print("Server running on port 50051...")
    server.start()
    server.wait_for_termination()

if __name__ == "__main__":
    init_db()
    serve()
