import base64
import socket
import ssl

targets = []
subject = ''
attachments = []

host_addr = 'smtp.yandex.ru'
port = 465

#указать почту и пароль отправителя
user_name = ''
password = ''


def request(socket, request):
    socket.send((request + '\n').encode())
    recv_data = socket.recv(65535).decode()
    return recv_data


def parse_cfg():
    global targets, subject, attachments
    with open('config.txt', encoding='utf-8') as cfg:
        targets = cfg.readline().split()
        if len(targets) == 0:
            print("write the recipient's e-mail")
        subject = cfg.readline()[:-1]
        attachments = cfg.readline().split()


parse_cfg()
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
    client.connect((host_addr, port))
    client = ssl.wrap_socket(client)
    print(client.recv(1024))
    print(request(client, 'ehlo Olya'))
    base64login = base64.b64encode(user_name.encode()).decode()

    base64password = base64.b64encode(password.encode()).decode()
    print(request(client, 'AUTH LOGIN'))
    print(request(client, base64login))
    print(request(client, base64password))
    print(request(client, 'MAIL FROM:' + user_name))
    for recipient in targets:
        print(request(client, "RCPT TO:" + recipient))
    print(request(client, 'DATA'))

    def read_msg():
        with open('msg.txt', 'rb') as fil:
            return base64.b64encode(fil.read()).decode()

    def read_pict(name):
        try:
            with open(name, 'rb') as pic:
                return base64.b64encode(pic.read()).decode()
        except FileNotFoundError:
            print('There is no such file')

    def create_msg():
        bound = "bound12345678966"
        msg = ""
        msg += "From: " + user_name + "\n"
        msg += "To: " + ' '.join(targets) + "\n"
        msg += "Subject: =?utf-8?B?" + base64.b64encode(subject.encode()).decode() + "?=\n"
        msg += "MIME-Version: 1.0" + "\n"
        msg += 'Content-Type: multipart/mixed; boundary="' + bound +'"' "\n"
        msg += "\n"
        msg += "--" + bound + "\n"
        msg += 'Content-Type: text/plain; charset="UTF-8"\n'
        msg += "Content-Transfer-Encoding: base64\n\n"
        msg += read_msg() + "\n"
        for attachment in attachments:
            msg += "--" + bound + "\n"
            msg += 'Content-Disposition: attachment; filename="icon.png"\n' \
                'Content-Transfer-Encoding: base64\nContent-Type: image/png; name="{}"\n\n'.format(attachment)
            msg += read_pict(attachment) + "\n"
        msg += '--' + bound + "--\n.\n"

        return msg
    request(client, create_msg())
    with open("out.txt", "w") as f:
        f.write(create_msg())
