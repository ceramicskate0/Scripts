import BaseHTTPServer, SimpleHTTPServer
import ssl
import os

location=raw_input('Enter IP or Hostname of Server:')
port=raw_input('Enter dest port of Server:')

os.system("openssl req -new -x509 -keyout server.pem -out server.pem -days 365 -nodes")
httpd = BaseHTTPServer.HTTPServer((location, port), SimpleHTTPServer.SimpleHTTPRequestHandler)
httpd.socket = ssl.wrap_socket (httpd.socket, certfile='./server.pem', server_side=True)
httpd.serve_forever()
