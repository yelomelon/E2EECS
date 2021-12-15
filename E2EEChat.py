import base64
import hashlib
import os
import socket
import threading
import time
from random import SystemRandom

from Cryptodome.Cipher import AES

# 서버 연결정보; 자체 서버 실행시 변경 가능
# SERVER_HOST = "homework.islab.work"
SERVER_HOST = "192.168.0.118"
SERVER_PORT = 8080

connectSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
connectSocket.connect((SERVER_HOST, SERVER_PORT))

keyxchg_dict = dict()

aes_key = [0x10, 0x01, 0x15, 0x1B, 0xA1, 0x11, 0x57, 0x72, 0x6C, 0x21, 0x56, 0x57, 0x62, 0x16, 0x05, 0x3D,
           0xFF, 0xFE, 0x11, 0x1B, 0x21, 0x31, 0x57, 0x72, 0x6B, 0x21, 0xA6, 0xA7, 0x6E, 0xE6, 0xE5, 0x3F]

global credential

prng = SystemRandom()
p = 1321
g = 131
secret_num = prng.randint(1, 100)
global A


class AES256CBC:
    class InvalidBlockSizeError(Exception):
        """Raised for invalid block sizes"""
        pass

    def __init__(self, key, bs=16):
        self.bs = bs
        self.iv = bytes([0x00] * 16)
        self.crypto = AES.new(key, AES.MODE_CBC, self.iv)

    def pad(self, text):
        return text + (self.bs - len(text.encode('utf-8')) % self.bs) * chr(self.bs - len(text.encode('utf-8')) % self.bs)

    def unpad(self, text):
        return text[:-ord(text[len(text) - 1:])]

    def encrypt(self, data):
        data = self.pad(data)
        data = data.encode("utf8")
        enc = self.crypto.encrypt(data)
        return base64.b64encode(enc)

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        enc = self.crypto.decrypt(enc)
        data = enc.decode("utf-8")
        return self.unpad(data)


def generate_A():
    global secret_num
    print("A: " + str(g ** secret_num % p))
    return g ** secret_num % p


def socket_read():
    while True:
        readbuff = connectSocket.recv(2048)

        if len(readbuff) == 0:
            continue

        recv_payload = readbuff.decode('utf-8')
        parse_payload(recv_payload)


# def socket_send():
#     while True:
#         str = input("MESSAGE: ")
#
#         send_bytes = str.encode('utf-8')
#
#         connectSocket.sendall(send_bytes)


def socket_send():
    global credential

    while True:
        time.sleep(0.3)

        choice = input('\n\033[96m' +
                       '0. Connect\n' +
                       '1. Key Exchange\n' +
                       '2. Key Exchange Reset\n' +
                       '3. Send Message\n' +
                       '4. Disconnect\n' +
                       '\033[95m' + 'Please Choose Number: ' + '\033[0m\n')

        if choice == '0':
            global credential
            credential = input("Credential: ")
            send_connect()

        elif choice == '1':  # Exchange Key
            input_to = input("To: ")
            send_keyxchg(input_to)

        elif choice == '2':  # Reset Key Exchange
            input_to = input("To: ")
            send_keyxchgrst(input_to)

        elif choice == '3':  # Send Message
            input_to = input("To: ")
            input_msg = input("MESSAGE: ")
            send_msgsend(input_to, input_msg)

        elif choice == '4':  # Disconnect
            send_disconnect()


def sec_key(lines, cred):
    global secret_num
    B = int(lines[6])
    secKey = hashlib.sha256(str(B ** secret_num % p).encode('utf-8')).digest()
    return secKey


def parse_payload(payload):
    global A
    # 수신된 페이로드를 여기서 처리; 필요할 경우 추가 함수 정의 가능
    lines = payload.split("\n")

    if lines[0].split(" ")[1] == "KEYXCHG":
        cred_from = lines[2][5:]
        if cred_from not in keyxchg_dict:
            send_keyxchgok(cred_from)
            send_keyxchg(cred_from)
            secKey = sec_key(lines, cred_from)
            keyxchg_dict.setdefault(cred_from, secKey)
        elif keyxchg_dict.get(cred_from) is None:
            secKey = sec_key(lines, cred_from)
            keyxchg_dict.update({cred_from: secKey})
            send_keyxchgok(cred_from)
        else:  # 키 교환 중복 요청 시
            send_keyxchgfail(cred_from)

    # key exchange reset
    elif lines[0].split(" ")[1] == "KEYXCHGRST":
        cred_from = lines[2][5:]
        if cred_from not in keyxchg_dict:
            pass
        elif keyxchg_dict.get(cred_from) is None:
            send_keyxchgok(cred_from)
            secKey = sec_key(lines, cred_from)
            keyxchg_dict.update({cred_from: secKey})
        else:
            send_keyxchgok(cred_from)
            send_keyxchg(cred_from)
            secKey = sec_key(lines, cred_from)
            keyxchg_dict.setdefault(cred_from, secKey)

    # 메시지 수신 시 복호화
    elif lines[0].split(" ")[1] == "MSGRECV":
        cred_from = cred_from = lines[2][5:]
        # aes_key = keyxchg_dict.get(cred_from)
        aes = AES256CBC(bytes(aes_key))

        lines[5] = aes.decrypt(lines[5].encode())
        str_n = ""
        for l in lines:
            str_n += l + "\n"
        payload = str_n

    print("\n================")
    print(payload)
    print("================\n")

    pass


def send_connect():
    global credential
    connect_bytes = ("3EPROTO CONNECT\nCredential: " + credential).encode('utf-8')
    connectSocket.sendall(connect_bytes)


def send_keyxchg(to, algo="AES-256-CBC"):
    global credential
    global A
    A = generate_A()
    A_str = str(A)
    keyxchg_bytes = ("3EPROTO KEYXCHG\n"
                     "Algo: " + algo + "\n"
                     "From: " + credential + "\n"
                     "To: " + to +
                     "\n\n" + A_str).encode('utf-8')
    connectSocket.sendall(keyxchg_bytes)
    if to not in keyxchg_dict:
        keyxchg_dict.setdefault(to, None)


def send_keyxchgfail(to, algo="AES-256-CBC"):
    global credential
    keyxchgfail_bytes = ("3EPROTO KEYXCHGFAIL\n"
                         "Algo: " + algo + "\n"
                         "From: " + credential + "\n"
                         "To: " + to).encode('utf-8')
    connectSocket.sendall(keyxchgfail_bytes)


def send_keyxchgok(to, algo="AES-256-CBC"):
    global credential
    keyxchgok_bytes = ("3EPROTO KEYXCHGOK\n"
                       "Algo: " + algo + "\n"
                       "From: " + credential + "\n"
                       "To: " + to).encode('utf-8')
    connectSocket.sendall(keyxchgok_bytes)


def send_keyxchgrst(to, algo="AES-256-CBC"):
    global credential
    A = generate_A()
    A_str = str(A)
    keyxchgrst_bytes = ("3EPROTO KEYXCHGRST\n"
                        "Algo: " + algo + "\n"
                        "From: " + credential + "\n"
                        "To: " + to +
                        "\n\n" + A_str).encode('utf-8')
    connectSocket.sendall(keyxchgrst_bytes)
    if to not in keyxchg_dict:
        keyxchg_dict.setdefault(to, None)
    else:
        keyxchg_dict.update({to: None})


def send_msgsend(to, msg, nonce="A/Xqf"):
    global credential
    if to not in keyxchg_dict:
        print("Message Send Fail")
        return
    # aes_key = keyxchg_dict.get(to)
    aes = AES256CBC(bytes(aes_key))
    msg_enc = (aes.encrypt(msg)).decode()

    send_bytes = ("3EPROTO MSGSEND\n"
                  "From: " + credential + "\n"                  
                  "To: " + to + "\n"
                  "Nonce: " + nonce +
                  "\n\n" + msg_enc + "").encode('utf-8')
    connectSocket.sendall(send_bytes)
    print(keyxchg_dict)


def send_disconnect():
    global credential
    disconnect_bytes = ("3EPROTO DISCONNECT\nCredential: " + credential).encode('utf-8')
    connectSocket.sendall(disconnect_bytes)

    time.sleep(1)
    input("press enter to exit")
    os._exit(1)


if __name__ == "__main__":
    # 동작
    reading_thread = threading.Thread(target=socket_read)
    sending_thread = threading.Thread(target=socket_send)

    reading_thread.start()
    sending_thread.start()

    reading_thread.join()
    sending_thread.join()
