# Place your imports here
import signal
import sys
import threading
from optparse import OptionParser
import socket
import select
import re

MAX_REQUEST_LEN = 2048

# Signal handler for pressing ctrl-c
def ctrl_c_pressed(signal, frame):
    sys.exit(0)

def origin_msg(method, host, add_headers=""):
    return f"GET {method} HTTP/1.0\n" \
           f"Host: {host}\n" \
           f"Connection: close\n" \
           f"{add_headers}\n"

def handle_client(client, client_addr):
    message = client.recv(MAX_REQUEST_LEN).decode()

    site, port, method, headers, err = check_message(message)

    # forward to socket connected to end address
    end_add = (site, int(port))
    end_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    end_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    end_sock.connect(end_add)
    # client_sock.send(bytes("Server response", "utf-8"))
    resp = origin_msg(method, site, headers)
    end_sock.sendall(resp.encode())
    # end_resp = end_sock.recv()
    # end_resp = receive_data()
    end_resp = end_sock.recv(MAX_REQUEST_LEN)

    print(f"{end_resp.decode('utf-8')}")
    # end_sock.shutdown(socket.SHUT_WR)
    end_sock.close()

    # relay to client
    client.send(end_resp)
    # client_sock.shutdown(socket.SHUT_WR)
    client.close()

def check_message(message):
    request = re.search(
        r"([^\s]+)\s(http:\/\/)([^\s:\/]+):?([^\/]+)?(\/[^\s]*)\s([^\n]+)\n?([^\s:]+: .+\n?)*",
        message)

    # initialize variables
    req = protocol = site = port = method = version = headers = err = None

    try:
        # check for GET request
        req = request.group(1)
        if req is None:
            raise AttributeError("nothing where GET expected.")
        if req != 'GET':
            if req == 'HEAD' or req == 'POST':
                raise NotImplementedError("HEAD or POST where GET expected.")
            else:
                raise AttributeError("unexpected non-GET request.")

        # check protocol
        protocol = request.group(2)
        if protocol is None:
            raise AttributeError("missing or malformed protocol")

        # check to make sure host is present
        site = request.group(3)
        if site is None:
            raise AttributeError("no host url.")

        # check to see if port is present
        port = request.group(4)
        if port is None:
            port = '80'

        # check the method/action to take, make sure at least something is there
        method = request.group(5)
        if method is None:
            raise AttributeError("no method.")

        # check to make sure the http version is present and HTTP/1.0
        version = request.group(6)
        if version is None:
            raise AttributeError("no http version declared.")
        if version != 'HTTP/1.0':
            if 'HTTP/1.1' in version:
                raise NotImplementedError("no support for HTTP/1.1.")
            # if 'HTTP/1.0' in version:
            #     raise AttributeError(f"right http version, other elements present: {version}.")
            # raise NotImplementedError("wrong http version.")

        # check to see if there are extra headers and make sure they are properly formatted
        headers = request.group(7)
        if headers is None:
            headers = ""
        elif not bool(re.match(r"([^\s]+: [^\s]+\n?)", headers)):
            raise AttributeError("headers malformed")

        # is the request is longer than what matched in the regex,
        # something is there that isn't supposed to be there
        if len(request.group(0)) != len(message):
            raise AttributeError("message length does not match request length.")
    except AttributeError as e:
        err = bytes(f"HTTP/1.0 400 Bad Request", "utf-8")
        return site, port, method, headers, err
    except NotImplementedError as e:
        err = bytes(f"HTTP/1.0 501 Not Implemented", "utf-8")
        return site, port, method, headers, err
    return site, port, method, headers, err


# Set up signal handling (ctrl-c)
signal.signal(signal.SIGINT, ctrl_c_pressed)

parser = OptionParser()
parser.add_option('-p', type='int', dest='serverPort')
parser.add_option('-a', type='string', dest='serverAddress')
(options, args) = parser.parse_args()

port = options.serverPort
address = options.serverAddress
if address is None:
    address = 'localhost'
if port is None:
    port = 2100

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((address, port))
    server.listen(100)
    server.setblocking(0)
    print(f"listening at {address} on port: {port}")

    # receiving clients
    while True:
        r, w, e = select.select((server,), (), (), 1)
        for l in r:
            client_sock, client_add = server.accept()
            threading.Thread(target=handle_client(client_sock, client_add), args=(client_sock,)).start()


