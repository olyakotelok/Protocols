from socket import *
from constants import *
from dnslib import DNSRecord, DNSHeader, DNSQuestion
import pickle
import time

from DNSServer.constants import FORWARDER, REV_TYPES_DICT, TYPES_DICT, PORT, HOST

cache = {}


def save_cache():
    cache['time'] = int(time.time())
    with open('cache.txt', 'wb') as cache_file:
        pickle.dump(cache, cache_file)


def load_cache():
    global cache
    try:
        with open('cache.txt', 'rb') as cache_file:
            info = pickle.load(cache_file)
        for key, record in info.items():
            if key != 'time':
                cache[key] = []
                for rec in record:
                    if info['time'] + rec.ttl > int(time.time()):
                        cache[key].append(rec)
    except FileNotFoundError:
        pass


def take_from_cache(key, ident):
    name = '.'.join(key.split('.')[:-1])
    header = DNSHeader(id=ident, aa=0, qr=1, ra=1, rcode=0)
    question = DNSQuestion(name, REV_TYPES_DICT[key.split('.')[-1]])
    answer = DNSRecord(header=header, q=question)
    for rec in cache[key]:
        answer.add_answer(rec)
    return answer.pack()


def cache_info(info):
    for item in info:
        name = '.'.join(map(lambda x: x.decode(), item.rname.label)) + '.'
        try:
            r_type = TYPES_DICT[int(item.rtype)]
        except KeyError:
            print('Unsupported type! Code: ', item.rtype)
            continue
        if name + r_type not in cache.keys():
            cache[name + r_type] = []
        cache[name + r_type].append(item)
    save_cache()


def send_req(msg):
    try:
        with socket(AF_INET, SOCK_DGRAM) as send_sock:
            send_sock.sendto(msg, (FORWARDER, PORT))
            send_sock.settimeout(3)
            data, addr = send_sock.recvfrom(1024)
            return data
    except gaierror:
        print("No internet connection!")
        exit()


def parse_req(msg):
    name = ''
    not_all = True
    marker = int(msg[0])
    while not_all:
        name += msg[1: marker + 1].decode('utf-8') + '.'
        msg = msg[marker + 1:]
        marker = int(msg[0])
        if marker == 0:
            not_all = False
    try:
        req_type = TYPES_DICT[int.from_bytes(msg[1:3], 'big')]
    except KeyError:
        req_type = 'A'
    key = name + req_type
    return key


def main():
    listen_sock = socket(AF_INET, SOCK_DGRAM)
    listen_sock.bind((HOST, PORT))

    while True:
        data, addr = listen_sock.recvfrom(2048)
        ident = int.from_bytes(data[:2], 'big')
        key = parse_req(data[12:])
        if key in cache.keys() and len(cache[key]) > 0:
            resp = take_from_cache(key, ident)
        else:
            resp = send_req(data)
            parsed = DNSRecord.parse(resp)
            if len(parsed.ar) > 0:
                cache_info(parsed.ar)
            if len(parsed.rr) > 0:
                cache_info(parsed.rr)
            if len(parsed.auth) > 0:
                cache_info(parsed.auth)
        listen_sock.sendto(resp, addr)


if __name__ == '__main__':
    load_cache()
    main()
