
import socket

HOST = "127.0.0.1"
PORT = 5050


def start_client():
    client = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    try:
        client.connect((HOST, PORT))

        print("[+] Connected to local server.")
        print("Type 'exit' to disconnect.")

        while True:
            message = input("Message: ")

            if message.lower() == "exit":
                break

            client.sendall(message.encode("utf-8"))

            response = client.recv(4096)

            print(
                "[SERVER]",
                response.decode("utf-8")
            )

    except ConnectionRefusedError:
        print("[!] Start the server first.")

    finally:
        client.close()


if __name__ == "__main__":
    start_client()
