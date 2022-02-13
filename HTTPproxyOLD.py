# Place your imports here
import signal
import sys
import threading
from optparse import OptionParser
import socket
import select
import re

MAX_REQUEST_LEN = 2048


def origin_msg(origin_method, host, add_headers=""):
    return f"GET {origin_method} HTTP/1.0\n" \
           f"Host: {host}\n" \
           f"Connection: close\n" \
           f"{add_headers}\n"


# Signal handler for pressing ctrl-c
def ctrl_c_pressed(signal, frame):
    sys.exit(0)


# Set up signal handling (ctrl-c)
signal.signal(signal.SIGINT, ctrl_c_pressed)


class HTTPproxy:
    def __init__(self):
        self.main(self)

    def main(self):
        parser = OptionParser()
        parser.add_option('-p', type='int', dest='serverPort')
        parser.add_option('-a', type='string', dest='serverAddress')
        (options, args) = parser.parse_args()

        self.port = options.serverPort
        self.address = options.serverAddress
        if self.address is None:
            self.address = 'localhost'
        if self.port is None:
            self.port = 2100

        # TODO: Set up sockets to receive requests
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as self.s:
            self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # self.s.settimeout(10.0)
            self.s.bind((self.address, self.port))
            self.s.listen(100)
            print(f"listening at {self.address} on port: {self.port}")

            threads_arr = []
            while True:
                r, w, e = select.select((self.s,), (), (), 1)
                for l in r:
                    self.client_sock, self.client_add = self.s.accept()
                    threading.Thread(target=self.handle_client(), args=(self.client_sock,)).start()

    def handle_client(self):
        # accept client connections
        # print(f"Connection with {client_add} established.")

        # message = receive_data()
        message = self.client_sock.recv(MAX_REQUEST_LEN).decode("utf-8")
        if message == '':
            return
        # message = receive_data(client_sock)

        # TODO: check if the message is properly formatted
        try:
            # first line <method> <url> <http version>

            client_req = re.search(
                r"([^\s]+)\shttp:\/\/([^\s:\/]+):?([^\/]+)?(\/[^\s]*)?\s([^\n]+)\n?(.+\n?)*",
                message,
                flags=re.S)

            # check for GET request
            req_type = client_req.group(1)
            if req_type is None:
                raise AttributeError("nothing where GET expected.")
            if req_type != 'GET':
                if req_type == 'HEAD' or req_type == 'POST':
                    raise NotImplementedError("HEAD or POST where GET expected.")
                else:
                    raise AttributeError("unexpected non-GET request.")

            # check to make sure host is present
            origin = client_req.group(2)
            if origin is None:
                raise AttributeError("no host url.")

            # check to see if port is present
            sPort = client_req.group(3)
            if sPort is None:
                sPort = '80'

            # check the method/action to take, make sure at least something is there
            method = client_req.group(4)
            if method is None:
                raise AttributeError("no method.")

            # check to make sure the http version is present and HTTP/1.0
            version = client_req.group(5)
            if version is None:
                raise AttributeError("no http version declared.")
            if version != 'HTTP/1.0':
                if 'HTTP/1.1' in version:
                    raise NotImplementedError("no support for HTTP/1.1.")
                # if 'HTTP/1.0' in version:
                #     raise AttributeError(f"bad headers: {version}.")
                # raise NotImplementedError("wrong http version.")

            # check to see if there are extra headers and make sure they are properly formatted
            headers = client_req.group(6)
            if headers is None:
                headers = ""
            elif not bool(re.match(r"([^\s]+: [^\s]+\n?)", headers)):
                raise AttributeError("headers malformed")

            # is the request is longer than what matched in the regex,
            # something is there that isn't supposed to be there
            if len(client_req.group(0)) != len(message):
                raise AttributeError("message length does not match request length.")
        except AttributeError as e:
            self.client_sock.send(bytes(f"HTTP/1.0 400 Bad Request\n{e}", "utf-8"))
            return
            # client_sock.shutdown(socket.SHUT_WR)
            # client_sock.close()
            # client_dead = True
        except NotImplementedError as e:
            self.client_sock.send(bytes(f"HTTP/1.0 501 Not Implemented\n{e}", "utf-8"))
            return
            # client_sock.shutdown(socket.SHUT_WR)
            # client_sock.close()
            # client_dead = True

        # print(f"Connection from {client_add} has been established. \n{message}")
        # forward to socket connected to end address
        end_ip = origin
        self.port = sPort
        end_add = (end_ip, int(self.port))
        end_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        end_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        end_sock.connect(end_add)
        # client_sock.send(bytes("Server response", "utf-8"))
        resp = origin_msg(method, end_ip, headers)
        end_sock.sendall(resp.encode())
        # end_resp = end_sock.recv()
        # end_resp = receive_data()
        end_resp = end_sock.recv(MAX_REQUEST_LEN)

        print(f"{end_resp.decode('utf-8')}")
        # end_sock.shutdown(socket.SHUT_WR)
        end_sock.close()

        # relay to client
        self.client_sock.send(end_resp)
        # client_sock.shutdown(socket.SHUT_WR)
        self.client_sock.close()


proxy = HTTPproxy()
