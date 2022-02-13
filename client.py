import socket

# setup socket
server_name = 'localhost'
server_port = 2100
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((server_name, server_port))

# message
# message = input("Enter content to send to server: \n")
message = "GET http://www.flux.utah.edu:80/cs4480/simple.html HTTP/1.0\r\nConnection: keep-alive\r\nheader: 2\r\n\r\n"
s.send(message.encode())

# server response
response = s.recv(1024)
print(f"{response.decode('utf-8')}")
s.close()
