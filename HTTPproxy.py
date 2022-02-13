# PREFACE: I'm quite salty (and dumb) that I just realized this entire goddamn assignment
# is only for part A of the p1.pdf. I ended up doing part B in a vain effort to distract
# myself from fighting all the garbage regex I was making so that's what the threading
# things are all about.

# Place your imports here
import signal
import sys
import threading
from optparse import OptionParser
import socket
import select
import re
from urllib.parse import urlparse

# MAX_REQUEST_LEN = 20971520
MAX_REQUEST_LEN = 1024


# Signal handler for pressing ctrl-c
def ctrl_c_pressed(signal, frame):
    sys.exit(0)


def origin_msg(method, host, headers):
    fheaders = ""
    for fhead in headers:
        fheaders += f"{fhead}\r\n"
    return f"GET {method} HTTP/1.0\r\n" \
           f"Host: {host}\r\n" \
           f"Connection: close\r\n" \
           f"{fheaders}\r\n\r\n"


def rec_data(sock):
    total_data = []
    data = ''
    End = "\r\n\r\n"
    while True:
        data = sock.recv(MAX_REQUEST_LEN)
        data = data.decode()
        if End in data:
            total_data.append(data[:data.find(End)])
            break
        total_data.append(data)
        if len(total_data) > 1:
            # check if end_of_data was split
            last_pair = total_data[-2] + total_data[-1]
            if End in last_pair:
                total_data[-2] = last_pair[:last_pair.find(End)]
                total_data.pop()
                break
    return ''.join(total_data)+"\r\n\r\n"


def check_message(message):
    lines = message.split(sep="\r\n")
    # request = re.search(
    #     r"([^\s]+)\s(http:\/\/)([^\s:\/]+)(:[0-9]+)?(\/[^\s]*)\s([^\n]+)[\n]?([\w-]+: .+\n)*",
    #     message)

    # deal with the first line
    request = lines[0].split(sep=" ")
    # initialize variables
    req = scheme = site = port = method = version = headers = err = None

    try:
        # check length of request
        if len(request) != 3:
            raise AttributeError("malformed request")

        # check for GET request
        req = request[0]
        if req is None:
            raise AttributeError("nothing where GET expected.")
        if req != "GET":
            if req == "HEAD" or req == "POST":
                raise NotImplementedError(f"HEAD or POST where GET expected.")
            else:
                raise AttributeError("unexpected non-GET request.")

        # split url using urllib
        url_full = urlparse(request[1], scheme='', allow_fragments=False)

        # check scheme
        scheme = url_full.scheme
        if scheme == '' or scheme != "http":
            raise AttributeError("missing or malformed scheme")

        # check to make sure host is present
        site = url_full.hostname
        if site is None:
            raise AttributeError("no host url.")

        # check to see if port is present
        port = url_full.port
        if port is None:
            port = 80

        # check the method/action to take, make sure at least something is there
        method = url_full.path
        if method == '':
            raise AttributeError("no method.")

        # check to make sure the http version is present and HTTP/1.0
        version = request[2]
        # print(f"{version} being checked...", file=sys.stdout)
        version_parts = re.search(r"^HTTP\/([0-9])\.([0-9])$", version)
        major = version_parts.group(1)
        minor = version_parts.group(2)
        if version_parts.group(1) != "1":
            # could be >1 or 0
            # print(f"{version} has bad major version", file=sys.stderr)
            if version_parts.group(1) == "0":
                # upgrade the http version
                version = "HTTP/1.0"
        elif version_parts.group(2) != "0":
            # error, higher versions not supported
            # print(f"{message} contained invalid version: {version}\n", file=sys.stderr)
            raise AttributeError("versions higher than 1.0 not supported")

        # check to see if there are extra headers and make sure they are properly formatted
        headers = lines[1:]
        headers = list(filter(None, headers))
        if headers is None or headers == ['']:
            headers = ""
        for i in range(len(headers)):
            if not bool(re.match(r"^([^()<>@,;:\\\"{}\s\t]+): (.*)$", headers[i])):
                raise AttributeError("headers malformed")
            if "Connection: keep-alive" in headers[i]:
                headers[i] = "Connection: close"

    except AttributeError as e:
        err = bytes(f"HTTP/1.0 400 Bad Request\r\n\r\n", "utf-8")
        # client.send("HTTP/1.0 400 Bad Request\r\n\r\n".encode())
        # client.close()
        return site, port, method, headers, err
    except NotImplementedError as e:
        err = bytes(f"HTTP/1.0 501 Not Implemented\r\n\r\n", "utf-8")
        # client.send("HTTP/1.0 501 Not Implemented\r\n\r\n".encode())
        # client.close()
        return site, port, method, headers, err
    except ValueError as e:
        err = bytes(f"HTTP/1.0 505 HTTP Version Not Supported\r\n\r\n", "utf-8")
        return site, port, method, headers, err
    return site, port, method, headers, err


def handle_client(client, client_addr):
    message = rec_data(client)
    # message = client.recv(MAX_REQUEST_LEN).decode()

    site, port, method, headers, err = check_message(message)
    if err:
        client.send(err)
        client.close()
        return
    # client.close()
    # forward to socket connected to end address
    end_add = (site, port)
    end_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    end_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    end_sock.connect(end_add)
    end_sock.sendall(origin_msg(method, site, headers).encode())
    end_resp = b''
    total_end_resp = []
    data = ''
    while True:
        data = end_sock.recv(MAX_REQUEST_LEN)
        if len(data) == 0:
            break
        total_end_resp.append(data)
    end_resp = b''.join(total_end_resp)



    # print(f"{end_resp.decode('utf-8')}")
    # end_sock.shutdown(socket.SHUT_WR)
    end_sock.close()

    # relay to client
    client.send(end_resp)
    # # client_sock.shutdown(socket.SHUT_WR)
    client.close()

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
    # server.setblocking(0)
    # print(f"listening at {address} on port: {port}")

    while True:
        r, w, e = select.select((server,), (), (), 1)
        for l in r:
            client_sock, client_add = server.accept()
            threading.Thread(target=handle_client, args=(client_sock, client_add)).start()


