
import socket

HOST = "127.0.0.1"
PORT = 5050


def start_server():
    server = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    server.setsockopt(
        socket.SOL_SOCKET,
        socket.SO_REUSEADDR,
        1
    )

    server.bind((HOST, PORT))
    server.listen(1)

    print(f"[*] Server listening on {HOST}:{PORT}")

    try:
        while True:
            connection, address = server.accept()

            with connection:
                print(f"[+] Connected: {address}")

                while True:
                    data = connection.recv(4096)

                    if not data:
                        break

                    message = data.decode(
                        "utf-8",
                        errors="replace"
                    )

                    print(f"[CLIENT] {message}")

                    response = f"Server received: {message}"
                    connection.sendall(
                        response.encode("utf-8")
                    )

    except KeyboardInterrupt:
        print("\n[*] Server shutting down.")

    finally:
        server.close()


if __name__ == "__main__":
    start_server()
