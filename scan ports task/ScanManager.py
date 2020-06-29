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

