import socket

MAX_REQUEST_LEN = 8


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


# setup socket
server_name = 'localhost'
server_port = 2100
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((server_name, server_port))

# message
# message = input("Enter content to send to server: \n")
message = "GET http://www.flux.utah.edu:80/cs4480/simple.html HTTP/1.0\r\nConnection: keep-alive\r\n\r\n"
s.send(message.encode())

# server response
# response = rec_data(s)
response = b''
total_response = []
while True:
    data = s.recv(MAX_REQUEST_LEN)
    if len(data) == 0:
        break
    total_response.append(data)
response = b''.join(total_response)
print(f"{response}")
s.close()
