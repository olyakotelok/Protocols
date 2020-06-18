import socket
import ssl
import select

HOST = "pop.yandex.ru"
PORT = 995

#почта и пароль, откуда читаем письма. Yandex
USERNAME = ""
PASS = ""


def send_cmd(cmd, sock):
    sock.send((cmd + '\r\n').encode())

    return read_responce(sock, 1)


def read_responce(sock, timeout):
    responce = ' '

    while True:
        r, _, _ = select.select([sock], [], [], timeout)

        if len(r) == 0:
            break
        part = sock.recv(1024).decode()

        responce += part
    return responce


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s = ssl.wrap_socket(s, ssl_version=ssl.PROTOCOL_SSLv23)

    s.connect((HOST, PORT))

    print(read_responce(s, 1))

    print(send_cmd(f'USER {USERNAME}', s))

    print(send_cmd(f'PASS {PASS}', s))
    print(send_cmd(f'STAT', s))
    print(send_cmd(f'LIST', s))
    #последнее полученное сообщение
    print(send_cmd('RETR 1', s))
