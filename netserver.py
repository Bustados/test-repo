import json
import select
import socket  # Import socket module
import sys
import util


class Server:

    """
    The constructor for the class Server
    """
    def __init__(self, ip, tcp_port):

        # server's ip
        if ip is None:
            tcip = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            tcip.connect(("yahoo.com", 80))
            socknames = tcip.getsockname()

            print(socknames)

            localip = socknames[0]
            tcip.close()

            self.ip = localip

        else:
            self.ip = ip

        # self.ip = "127.0.0.1"
        # self.ip = socket.gethostbyname(socket.gethostname())

        # port for tcp server
        self.tcp_port = tcp_port

        # dictionary for list of files - keys will be the clients ip, values will be a list of files
        self.files = {}

        # running list of clients who are active and connected
        # self.clients = []

        # server tcp socket
        self.server_tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # self.server_tcp_socket.setblocking(0)
        print("Server Socket created")

        # Bind socket to localhost and port
        try:
            self.server_tcp_socket.bind((self.ip, self.tcp_port))
            self.server_tcp_socket.listen(5)

        # catch any socket errors
        except() as e:
            print("Bind failed: {}".format(repr(e)))
            import sys
            sys.exit()

        print("Socket bind complete: IP: {} PORT: {}".format(self.ip, self.tcp_port))

        # run server
        self.start()

    """
    Method to start the server tcp socket
    While True, wait and receive incoming connections and handle them (for now print what comes in)
    """
    def start(self):
        while True:
            try:
                connection, address = self.server_tcp_socket.accept()
                buffer = connection.recv(2048)
                print(buffer)

                buff_data = buffer.decode("utf8")
                print("Received: {}".format(buff_data))

                # If needed send a handshake, comment out if not needed
                connection.send(bytes("Update Proceeding", "utf8"))

                if buff_data == "close":
                    break

                elif buff_data == "update":
                    self.update_directory(connection, address)

                # If needed to send a handshake
                # connection.send(bytes("Received Data", "utf8"))

                # make sure to close the inbound connection
                connection.close()
                # break

            except KeyboardInterrupt as e:
                print("interrupted: {}".format(e))
            except() as e1:
                print(e1)

    def update_directory(self, connection, address):
        transfer_timeout = 10
        receive_buffer = 2048
        receiver_data = ""

        print("Server: Waiting for data...")

        while True:
            try:
                ready = select.select([connection], [], [], transfer_timeout)
                # print("Data for ready: {}".format(ready))

                if ready[0]:
                    upacket_recv = connection.recv(receive_buffer)
                    print("Server: Packet received from: {}".format(address))

                    if upacket_recv is not None:

                        print(upacket_recv)
                        upacket_unpack = util.unpack_struct(upacket_recv)

                        if upacket_unpack[3] == -1:
                            print("All Packets Received\n")
                            break

                        receiver_data += upacket_unpack[-1].decode('utf8')

                # if no response within 4 seconds close receiver
                else:
                    print("Server: Connection timeout err: {} second(s)".format(transfer_timeout))
                    connection.close()
                    break

            except socket.error as esocrr:
                print("Socket err: {}".format(esocrr))
                # print("Receiver: Socket error, dropping pkt")
                continue

            except KeyboardInterrupt:
                print("\nServer: Shutting down")
                connection.close()
                return

        obj_from_json = json.loads(receiver_data)
        obj_loc = obj_from_json["loc"]
        obj_files = obj_from_json["files"]

        files_obj = { obj_loc: obj_files }

        if obj_loc not in self.files:
            print("Added new client files")
            self.files.update(files_obj)
        else:
            skipped = 0

            for item in obj_files:
                if item not in self.files[obj_loc]:
                    self.files[obj_loc].append(item)
                else:
                    skipped += 1

            print("Updated existing clients files: {} file(s) were skipped".format(skipped))
            # if obj_files not in self.files[obj_loc]["files"]:
            #     print("Updated existing clients files")
            #     self.files[obj_loc]["files"].append(obj_files)
            # else:
            #     print("Files already in server, skipped")

        print(self.files)
        # self.files.update({})

        # print("Loc: {}".format())
        # print("Files: {}".format())
        # print(obj_from_json)

    """
    Method to send the server's ip to the given ip address and port
    """
    def return_location(self, ip, dest_port):
        try:
            tcip = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            tcip.connect((ip, dest_port))
            tcip.send(bytes("{}:{}".format(self.ip, self.tcp_port), 'utf8'))
            tcip.close()
            # self.server_tcp_socket.sendto(util.pack_struct(self.tcp_port, dest_port, 0, b"{}".format(self.ip)), (ip, dest_port))
        except() as e:
            print(e)


if __name__ == '__main__':
    if len(sys.argv) == 1:
        print("Usage of file:")
        print("Use 1: python netserver.py <port>")
        print("Use 2: python netserver.py <ip> <port>")

    elif len(sys.argv) == 2:
        c = Server(ip=None, tcp_port=int(sys.argv[-1]))

    else:
        c = Server(ip=sys.argv[-2], tcp_port=int(sys.argv[-1]))
