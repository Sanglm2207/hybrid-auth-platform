"""Loopback-only SMTP sink for isolated verification. Never forwards email."""
import email, socketserver, threading
from email import policy
class SMTPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address=True
    daemon_threads=True
    def __init__(self):
        self.messages=[];self.mutex=threading.Lock();self.available=True
        super().__init__(('127.0.0.1',0),SMTPHandler)
class SMTPHandler(socketserver.StreamRequestHandler):
    def handle(self):
        def reply(value):self.wfile.write((value+'\r\n').encode());self.wfile.flush()
        reply('220 isolated-smtp')
        while True:
            line=self.rfile.readline()
            if not line:return
            command=line.decode(errors='replace').split(' ',1)[0].strip().upper()
            if command in ('EHLO','HELO'):reply('250 isolated-smtp')
            elif command=='DATA':
                if not self.server.available:reply('451 Temporary failure');continue
                reply('354 End with dot');pieces=[]
                while True:
                    line=self.rfile.readline()
                    if not line:return
                    if line==b'.\r\n':break
                    pieces.append(line[1:] if line.startswith(b'..') else line)
                message=email.message_from_bytes(b''.join(pieces),policy=policy.default)
                with self.server.mutex:self.server.messages.append(message)
                reply('250 Accepted')
            elif command=='QUIT':reply('221 Bye');return
            elif command in ('MAIL','RCPT','RSET','NOOP'):reply('250 OK')
            else:reply('502 Unsupported')
