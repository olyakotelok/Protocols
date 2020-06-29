import threading
import socket
import struct
import datetime
import argparse


MESSAGE = 193 * b'Q'
BUFFER_SIZE = 1024


class ScanManager:
    def __init__(self, host, min_boundary_port, max_boundary_port, tcp_scan,
                 udp_scan, protocols_scan, threads_p):
        self.host = host
        self.min_boundary_port = int(min_boundary_port)
        self.max_boundary_port = int(max_boundary_port)
        if tcp_scan == "yes":
            self.tcp_scan = True
        else:
            self.tcp_scan =False

        if udp_scan == "yes":
            self.udp_scan = True
        else:
            self.udp_scan = False
        if protocols_scan == "yes":
            self.protocols_scan = True
        else:
            self.protocols_scan = False

        self.count_threads = int(threads_p)

    def scan(self):
        scanners = []
        threads_left = self.count_threads
        ports_count = self.max_boundary_port - self.min_boundary_port
        left = self.min_boundary_port

        for _ in range(self.count_threads):
            part = ports_count // threads_left
            right = left + part

            scanner = Scanner(self.host, left, right, self.tcp_scan, self.udp_scan, self.protocols_scan)
            scanners.append(scanner)
            scanner.start()

            threads_left -= 1
            ports_count -= part
            left = right

        for s in scanners:
            s.join()


class Scanner(threading.Thread):
    def __init__(self, host, left_boundary_port, right_boundary_port, need_tcp_scan, need_udp_scan, need_protocols_scan):
        super().__init__()
        self.host = host
        self.left_boundary_port = left_boundary_port
        self.right_boundary_port = right_boundary_port
        self.need_tcp_scan = need_tcp_scan
        self.need_udp_scan = need_udp_scan
        self.need_protocols_scan = need_protocols_scan
        self.opened_ports = []
        self.closed_ports = []
        self.tcp_checkers = [(self.scan_http, 'http'), (self.scan_smtp, 'smtp'),
                             (self.scan_pop3, 'pop3')]
        self.udp_checkers = [(self.scan_dns, 'dns'), (self.scan_sntp, 'sntp')]

    def run(self):
        self.scan()

    def scan(self):
        methods = []
        if self.need_tcp_scan:
            methods.append((self.scan_tcp, 'tcp'))
        if self.need_udp_scan:
            methods.append((self.scan_udp, 'udp'))
        for port in range(self.left_boundary_port, self.right_boundary_port):
            for scan_method, transport in methods:
                is_open = scan_method(port)
                if is_open:
                    if self.need_protocols_scan:
                        protocol = self.protocols_scan(port, transport)
                        self.print_result(transport, port, protocol)
                    else:
                        self.print_result(transport, port)

    def scan_tcp(self, port):
        is_open = False
        addr = (self.host, port)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        res = sock.connect_ex(addr)
        if res == 0:
            self.opened_ports.append(('tcp', port))
            is_open = True
        else:
            self.closed_ports.append(('tcp', port))
        sock.close()
        return is_open

    def scan_udp(self, port):
        is_open = False
        addr = (self.host, port)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        sock.sendto(MESSAGE, addr)
        try:
            d, ad = sock.recvfrom(1024)
        except ConnectionResetError:
            self.closed_ports.append(('udp', port))
        except socket.timeout:
            self.opened_ports.append(('udp', port))
            is_open = True
        finally:
            sock.close()
        return is_open

    def print_result(self, transport, port, protocol=None):
        if protocol is not None:
            print(transport + '/' + str(port) + '(' + protocol +')')
        else:
            print(transport + '/' + str(port))

    def protocols_scan(self, port, conn):
        if conn == 'udp':
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            checkers = self.udp_checkers
        elif conn == 'tcp':
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            checkers = self.tcp_checkers
        addr = (self.host, port)
        sock.settimeout(2)
        for scan_method, protocol_name in checkers:
            if scan_method(sock, addr):
                return protocol_name
        return None

    def send_data(self, sock, data, conn, addr):
        resp = b''
        try:
            if conn == 'udp':
                sock.sendto(data, addr)
                resp, _ = sock.recvfrom(BUFFER_SIZE)
            elif conn == 'tcp':
                sock.send(data)
                resp = sock.recv(BUFFER_SIZE)
        except socket.error:
            pass
        return resp

    def has_key_words(self, send_data, check_data, sock, conn, addr):
        resp = self.send_data(sock, send_data, conn, addr)
        for cdata in check_data:
            if cdata in resp:
                return True
        return False

    def check_if_correct(self, resp):
        return resp not in [None, b'']

    def scan_smtp(self, sock, addr):
        return self.has_key_words(b'EHLO a', [b'smtp', b'SMTP'], sock, 'tcp', addr)

    def scan_sntp(self, sock, addr):
        ntp_request = b'\xe3\x00\x03\xfa' + b'\x00\x01\x00\x00' * 2 + 28 * b'\x00'
        ntp_request += struct.pack('!I ', self.get_current_time()) + b'\x00' * 4
        resp = self.send_data(sock, ntp_request, 'udp', addr)
        return self.check_if_correct(resp)

    def scan_dns(self, sock, addr):
        google = b'\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x00'
        dns_query = (b'\xb9\x73\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
                     b'\x03\x77\x77\x77') + google + b'\x00\x01\x00\x01'
        resp = self.send_data(sock, dns_query, 'udp', addr)
        return self.check_if_correct(resp) and google in resp

    def scan_pop3(self, sock, addr):
        return self.has_key_words(b'test', [b'+OK POP', b'+OK pop'], sock, 'tcp', addr)

    def scan_http(self, sock, addr):
        return self.has_key_words(b'ping\r\n', [b'HTTP'], sock, 'tcp', addr)

    def get_current_time(self):
        diff = datetime.datetime.utcnow() - datetime.datetime(1900, 1, 1, 0, 0, 0)
        return diff.days * 24 * 60 * 60 + diff.seconds

def main():
    print("Hello. ")
    string_help = "Сканер портов. Проверка открытых udp и tcp портов. Вводим либо все параметры, либо ни одного. (надо доработать парсинг аргументов)"
    parser = argparse.ArgumentParser(string_help)

    parser.add_argument('-host', '--host',
                        help="хост")
    parser.add_argument('-mb', '--min_boundary',
                        help="нижняя граница поиска")
    parser.add_argument('-maxb', '--max_boundary',
                        help="верхняя граница поиска")
    parser.add_argument('-tcp', '--tcp_scan',
                        help="сканируем tcp? yes/no")
    parser.add_argument('-udp', '--udp_scan',
                        help="сканируем udp? yes/no")
    parser.add_argument('-other', '--other_scan',
                        help="сканируем остальное? yes/no",)
    parser.add_argument('-thr', '--threads_count',
                        help="число потоков. по дефолту не меньше 25")

    args = parser.parse_args()


    if args.host is None and args.tcp_scan is None and args.other_scan is None and args.threads_count is None and args.max_boundary is None and args.udp_scan is None\
            and args.min_boundary is None:
        print("Работаем по умолчанию")
        args.host = "127.0.0.1"
        args.min_boundary = 5004
        args.max_boundary = 5454
        args.tcp_scan="yes"
        args.udp_scan = "yes"
        args.other_scan= "yes"
        args.threads_count = 25
        # иначе он думает слишком долго!!

    else:
        print("Работаем с введенными параметрами")
    thread_p = args.threads_count
    scanner_manager = ScanManager(args.host, args.min_boundary, args.max_boundary,args.tcp_scan, args.udp_scan, args.other_scan, thread_p)
    scanner_manager.scan()

main()
