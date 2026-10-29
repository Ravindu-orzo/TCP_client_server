import socket
import sys

SERVER_IP = "127.0.0.1"
SERVER_PORT = 50645
BUFFER_SIZE = 4096

session_token = None


# -------------------------------
# Build framed message
# -------------------------------
def build_message(payload: str) -> bytes:
    payload_bytes = payload.encode()
    message = f"LEN:{len(payload_bytes)}\n".encode() + payload_bytes
    return message


# -------------------------------
# Receive full response
# -------------------------------
def receive_response(sock):
    data = b""
    while True:
        try:
            chunk = sock.recv(BUFFER_SIZE)
            if not chunk:
                break
            data += chunk
            # server responses end with newline
            if b"\n" in chunk:
                break
        except:
            break
    return data.decode()


# -------------------------------
# Send command and print response
# -------------------------------
def send_command(sock, payload):
    message = build_message(payload)
    sock.sendall(message)
    response = receive_response(sock)
    print(response)

    return response


# -------------------------------
# Extract token from login response
# -------------------------------
def extract_token(response):
    if "Token:" in response:
        return response.split("Token:")[1].strip()
    return None


# -------------------------------
# Main CLI Loop
# -------------------------------
def main():
    global session_token

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((SERVER_IP, SERVER_PORT))
        print("[+] Connection established..")
        print("========Available commands ===========")
        print("register [username] [password]")
        print("   login [username] [password]")
        print("======================================")

    except Exception as e:
        print("Connection failed:", e)
        sys.exit()

    while True:
        try:
            command = input(">> ").strip()

            # -------- REGISTER --------
            if command.startswith("register"):
                parts = command.split()
                if len(parts) != 3:
                    print("==============================")
                    print("Invalid values entered. correct usage: register [username] [password]")
                    print("==============================")
                    continue

                payload = f"REGISTER {parts[1]} {parts[2]}"
                send_command(sock, payload)

            # -------- LOGIN --------
            elif command.startswith("login"):
                parts = command.split()
                if len(parts) != 3:
                    print("==============================")
                    print("Invalid values entered. correct usage: login [username] [password]")
                    print("==============================")
                    continue

                payload = f"LOGIN {parts[1]} {parts[2]}"
                response = send_command(sock, payload)

                token = extract_token(response)
                if token:
                    session_token = token
                    print("[+] Session token stored...")

            # -------- LOGOUT --------
            elif command == "logout":
                if session_token:
                    payload = f"TOKEN:{session_token} LOGOUT"
                else:
                    payload = "LOGOUT"

                send_command(sock, payload)
                session_token = None

            # -------- GET --------
            elif command.startswith("get"):
                if not session_token:
                    print("Login to run protected commands!")
                    continue

                args = command[4:]
                payload = f"TOKEN:{session_token} GET {args}"
                send_command(sock, payload)

            # -------- SET --------
            elif command.startswith("set"):
                if not session_token:
                    print("Login to run protected commands!")
                    continue

                args = command[4:]
                payload = f"TOKEN:{session_token} SET {args}"
                send_command(sock, payload)

            # -------- EXIT --------
            elif command == "exit":
                print("Closing connection...")
                sock.close()
                break

            else:
                if session_token:
                    payload = f"TOKEN:{session_token} {command}"
                else:
                    payload = command

                send_command(sock, payload)

        except KeyboardInterrupt:
            print("\nExiting...")
            sock.close()
            break


if __name__ == "__main__":
    main()
