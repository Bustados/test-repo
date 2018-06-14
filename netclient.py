import socket  # Import socket module
import time  # Import time module
import os
import select
import sys
import uuid
import json
import util

# Client/Peer needs to have:
#   TCP when issuing a GET request to the server for a file
#   UDP when a client is issuing a

#   Close method(TCP):
#        when the client stops communicating, then remove the client from the servers client list

#   Query method(TCP):
#         to ask the server where the file is

#   Update method(TCP):
#         let the server know what files you have

#   QueryDirectory method(TCP):
#         ask the server for the entire file list

#   ConnectToPeer method(UDP):
#         establish a connection to a peer

#   SendData2Peer(UDP):
#          send the requested data to the peer requester

# For messages sent to the server (client to server) each packet needs host name and address


# server needs to have:
#   ReturnLocation:
#          when asked for the file, return the hostname and the ip of the peer that holds the file

#   UpdateDirectory:
#          when the peer has a new file, add to the list: name of the file, hostname, ip

#   ReturnDirectory:
#


# global variables
transfer_timeout = util.packet_transfer_timeout
receive_buffer = util.udp_mtu_size
file_read_size = util.udp_mtu_size


class Client:

    """
    The constructor for the class Client
    """
    def __init__(self, name, ip, udp_port, lmode=False):
        # give each client a name to identify
        self.name = name

        self.gen_packet_loss = lmode

        # client's ip address
        if ip is None:
            tcip = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            tcip.connect(("yahoo.com", 80))
            socknames = tcip.getsockname()

            # print(socknames)

            localip = socknames[0]
            tcip.close()

            self.ip = localip

        else:
            self.ip = ip

        # self.ip = socket.gethostbyname(socket.gethostname())

        # clients udp port
        self.port = udp_port

        print("Created Client = {} - {} : {}".format(self.name, self.ip, self.port))

        while True:
            try:
                command = input("Please enter a command: c = server close request, r = receive file, s = send file, "
                                "u = send directory listing, x = quit\n")

                if command == "x":
                    break

                elif command == "r":
                    self.receive_file()

                elif command == "s":
                    from tkinter import filedialog, Tk
                    root = Tk()
                    root.filename = filedialog.askopenfilename(title="Select file")
                    file_path = os.path.abspath(root.filename)
                    root.destroy()
                    # print(file_path)

                    if not file_path or (not os.path.exists(file_path)) or (not os.path.isfile(file_path)):
                        print("Path is invalid or path is a folder, please try send command again")
                        continue

                    dest_ip = self.ip
                    # dest_ip = input("Please enter the destination ip addr: ")

                    try:
                        dest_port = int(input("Please enter the destination port: "))
                    except(ValueError, Exception) as porterr:
                        print("Invalid port, please try send command again; err: {}".format(porterr))
                        continue

                    # # file_path = (input("Please enter the file path: "))
                    # file_path = os.path.join(input("Please enter the file path: "))
                    # # dest_ip = self.ip
                    # dest_ip = input("Please enter the destination ip addr: ")
                    # dest_port = int(input("Please enter the destination port: "))

                    self.send_file(file_path, dest_ip, self.port, dest_port)

                elif command == "u":
                    folder_path = os.path.join(input("Please enter the folder path: "))
                    dest_ip = input("Please enter the destination ip addr: ")
                    dest_port = int(input("Please enter the destination port: "))

                    self.update(dest_ip, dest_port, folder_path)

                elif command == "c":
                    dest_ip = input("Please enter the destination ip addr: ")
                    dest_port = int(input("Please enter the destination port: "))
                    print("Sending Server Close Request")
                    tsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    tsocket.connect((dest_ip, dest_port))
                    print("Sent Close Command")
                    tsocket.send(bytes("close", 'utf8'))





                    oxfisfmhimxfimixhm
                    tsocket.close()

                else:
                    print("Please enter a proper command!")

            except KeyboardInterrupt as e:
                pass

            except():
                print("err")

    def receive_file(self):
        expected_seq_num = 0

        file_name = ""

        tsocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        tsocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        tsocket.bind(('', self.port))
        # tsocket.connect(('', self.port))
        # tsocket.setblocking(0)

        session_key = None

        print("Receiver: Listening on {} : {}".format(self.ip, self.port))

        while True:
            try:
                print("Waiting for filename...")

                ready = select.select([tsocket], [], [], transfer_timeout)
                # print("Data for ready: {}".format(ready))

                if ready[0]:
                    # get filename from sender
                    data_recv2, rsconn2 = tsocket.recvfrom(receive_buffer)
                    file_name = data_recv2.decode('utf8')
                    print("Received filename: {}".format(file_name))
                    break

                # if no response within timeout skip
                else:
                    continue

            except socket.error as err:
                print("Socket err: {}".format(err))
                tsocket.close()
                return

            except KeyboardInterrupt:
                print("\nReceiver: Shutting down")
                tsocket.close()
                return

        """     Start receiving packets for file     """
        # Open output file
        try:
            fd = open(file_name, "wb")
        except():
            print("Failed to open file: {}".format(file_name))
            sys.exit(-1)

        while True:
            try:
                print("Receiver: Waiting for data...")

                ready = select.select([tsocket], [], [], transfer_timeout)
                # print("Data for ready: {}".format(ready))

                if ready[0]:
                    upacket_recv, sconnection = tsocket.recvfrom(receive_buffer)
                    print("Receiver: Packet received from: {}".format(sconnection))

                elif expected_seq_num == 0:
                    # print("Receiver: No data yet")
                    continue

                # if no response within 4 seconds close receiver
                else:
                    print("Receiver: Connection timeout err: {} second(s)".format(transfer_timeout))
                    tsocket.close()
                    fd.close()
                    break

            except socket.error as esocrr:
                # print("Receiver: Socket error, dropping pkt")
                print("Socket err: {}".format(esocrr))
                tsocket.close()
                return

            except KeyboardInterrupt:
                print("\nReceiver: Shutting down")
                tsocket.close()
                fd.close()
                return

            upacket_unpacked = util.unpack_struct(upacket_recv)

            # if this is the confirmation packet for all packets received, close and exit receiver
            if upacket_unpacked[3] == -1:
                print("Receiver: Received Confirmation Packet: {}".format(upacket_unpacked))
                print("Receiver: All Packets Received, File Received Successfully!\n")
                tsocket.close()
                fd.close()
                break

            print("Receiver: Received packet")
            # print("Receiver: Received packet: {}".format(upacket_unpacked))

            # Compute checksum
            upacket_chksum = upacket_unpacked[2]
            client_computed_chksum = util.checksum2(upacket_unpacked[-1])
            print("Checking checksum: {} - {}".format(upacket_chksum, client_computed_chksum))

            if upacket_chksum != client_computed_chksum:
                print("Receiver: Invalid checksum, packet dropped\n")
                continue

            # Check sequence number
            print("Checking sequence number: {} - {}".format(upacket_unpacked[3], expected_seq_num))
            if expected_seq_num != upacket_unpacked[3]:
                print("Receiver: Unexpected sequence number: {} - expected: {}\n".format(upacket_unpacked[3], expected_seq_num))
                continue

            # Generate artificial packet loss
            if self.gen_packet_loss:
                print("Generating delay: {} second(s), sequence number: {}".format(transfer_timeout, upacket_unpacked[3]))
                time.sleep(transfer_timeout)

            # Send ACK
            print("Receiver: Sending ack to: {}\n".format(sconnection))
            tsocket.sendto(util.pack_ack(upacket_unpacked), sconnection)
            expected_seq_num += 1

            # Write data to file
            try:
                received_data = upacket_unpacked[-1]
                print("Received data: {}".format(received_data))
                fd.write(received_data)
                fd.flush()

            except():
                print("Failed to open file: {}".format(file_name))

    def send_file(self, file_path, ip, src_port, dest_port):
        tsocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        tsocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        tsocket.bind(('', self.port))
        # tsocket.connect((self.ip, self.port))
        # tsocket.bind((self.ip, self.port))
        # tsocket.setblocking(0)

        session_key = None
        resend_try_count = 0
        max_resend_count = 10

        file_name = file_path[file_path.rfind("\\")+1:]
        file_name = file_name[:file_name.rfind(".")]+"_tr"+file_name[file_name.rfind("."):]

        print("Sending filename: {}".format(file_name))
        tsocket.sendto(bytes(file_name, 'utf8'), (ip, dest_port))

        # Build packet list
        upackets = util.read_file(file_path=file_path, sport=src_port, dport=dest_port)
        print("\nNumber of Packets to Send: {}\n".format(len(upackets)))

        # packet list index number
        upacket_seq_num = 0

        # number to keep track of the number of packets sent out that need acknowledgment
        upacket_ack_count = 0

        while upacket_seq_num < len(upackets):

            # if the previous packet was acknowledged, then this if will get executed
            # Can we send a packet, do we need to send pkt
            if upacket_ack_count < 1 and (upacket_ack_count + upacket_seq_num) < len(upackets):
                tsocket.sendto(upackets[upacket_seq_num + upacket_ack_count], (ip, dest_port))
                print("Sender: Sent packet to: {} : {}".format(ip, str(dest_port)))
                upacket_ack_count += 1
                continue

            # if we haven't gotten an acknowledgment from the server on the
            # last packet we've sent then the above if won't be executed, which means that we need
            # to listen for an acknowledgment of the sequence number of the last packet
            else:
                try:
                    # Listen for ACKs
                    ready = select.select([tsocket], [], [], transfer_timeout)

                    if ready[0]:
                        upacket_recv, sconnection = tsocket.recvfrom(receive_buffer)
                        print("Sender: Packet received from: {}".format(sconnection))

                    else:
                        # no ACK received before timeout
                        print("Sender: No packet received before timeout: {} - seq_num: {} - try: {}\n".format(
                            transfer_timeout, upacket_seq_num, resend_try_count))

                        if resend_try_count > max_resend_count:
                            print("Max packet resend count hit, shutting down file transfer")
                            tsocket.close()
                            return

                        upacket_ack_count = 0
                        resend_try_count += 1
                        continue

                    # unpack packet
                    upacket_ack_seqnum = util.unpack_ack(upacket_recv)

                    # If this is the pkt you're looking for
                    # the packet's sequence number is the acknowledgment
                    if upacket_ack_seqnum == upacket_seq_num:
                        # increment the sequence number to go to send the next packet in the packet list
                        upacket_seq_num += 1

                        # decrement the unacknowledged packet number because
                        # we've received the correct sequence number
                        upacket_ack_count -= 1
                        print("Sender: upacket_seq_num updated: {} - unacked updated: {}\n".format(upacket_seq_num, upacket_ack_count))

                    else:
                        print("Sender: Out of order packet, expected: {} - received: {}\n".format(upacket_seq_num, upacket_ack_seqnum))
                        upacket_ack_count = 0
                        continue

                except socket.error as socerr:
                    print("Sender: Socket error: {}".format(socerr))
                    tsocket.close()
                    return

                except KeyboardInterrupt:
                    print("\nSender: Shutting down")
                    tsocket.close()
                    return

        # send final packet to let receiver know all packets have been sent
        confirm_packet = util.pack_struct(0, 0, -1, b"EOF")
        tsocket.sendto(confirm_packet, (ip, dest_port))
        # Close server connection and exit successfully
        print("Sender: File Transferred Successfully!\n")
        tsocket.close()

    # def receive_file(self):
    #     expected_seq_num = 0
    #
    #     file_name = "testfile"
    #
    #     tsocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    #     tsocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    #     # tsocket.connect(('', self.port))
    #     tsocket.bind(('', self.port))
    #     # tsocket.setblocking(0)
    #
    #     # Open output file
    #     try:
    #         fd = open(file_name, "wb")
    #     except():
    #         print("Failed to open file: {}".format(file_name))
    #         sys.exit(-1)
    #
    #     print("Client: Listening on {} : {}".format(self.ip, self.port))
    #
    #     while True:
    #         try:
    #             print("Client: Ready for data, timeout started...")
    #
    #             ready = select.select([tsocket], [], [], util.packet_transfer_timeout)
    #             # print("Data for ready: {}".format(ready))
    #
    #             if ready[0]:
    #                 upacket_recv, sconnection = tsocket.recvfrom(util.udp_mtu_size)
    #                 print("Client: Packet received from: {}".format(sconnection))
    #
    #             elif expected_seq_num == 0:  # If no pkt has been received
    #                 # print("Client: No data yet")
    #                 continue
    #
    #             # if no response within 4 seconds close receiver
    #             else:
    #                 print("Client: Connection timeout err: {} second(s)".format(util.packet_transfer_timeout))
    #                 tsocket.close()
    #                 fd.close()
    #                 break
    #
    #         except socket.error:
    #             print("Client: Socket error, dropping pkt")
    #             continue
    #
    #         except KeyboardInterrupt:
    #             print("\nClient: Shutting down")
    #             tsocket.close()
    #             fd.close()
    #             break
    #
    #         upacket_unpacked = util.unpack_struct(upacket_recv)
    #
    #         # if this is the confirmation packet for all packets received, close and exit receiver
    #         if upacket_unpacked[3] == -1:
    #             print("Client: Received Confirmation Packet: {}".format(upacket_unpacked))
    #             print("Client: All Packets Received, File Received Successfully!")
    #             tsocket.close()
    #             fd.close()
    #             break
    #
    #         print("Client: Received packet: {}".format(upacket_unpacked))
    #
    #         # Compute checksum
    #         upacket_chksum = upacket_unpacked[2]
    #         client_computed_chksum = util.checksum2(upacket_unpacked[-1])
    #         print("Checking checksum: {} - {}".format(upacket_chksum, client_computed_chksum))
    #
    #         if upacket_chksum != client_computed_chksum:
    #             print("Client: Invalid checksum, packet dropped\n")
    #             continue
    #
    #         # Check sequence number
    #         print("Checking sequence number: {} - {}".format(upacket_unpacked[3], expected_seq_num))
    #         if expected_seq_num != upacket_unpacked[3]:
    #             print("Client: Unexpected sequence number: {} - expected: {}\n".format(upacket_unpacked[3], expected_seq_num))
    #             continue
    #
    #         # Generate artificial packet loss
    #         gen_packet_loss = False
    #         if gen_packet_loss:
    #             print("Generating delay: {} second(s), sequence number: {}".format(util.packet_transfer_timeout, upacket_unpacked[3]))
    #             time.sleep(util.packet_transfer_timeout)
    #
    #         # Send ACK
    #         print("Client: Sending ack to: {}\n".format(sconnection))
    #         tsocket.sendto(util.pack_ack(upacket_unpacked), sconnection)
    #         expected_seq_num += 1
    #
    #         # Write data to file
    #         try:
    #             buff = upacket_unpacked[-1]
    #             fd.write(buff)
    #             fd.flush()
    #
    #         except():
    #             print("Failed to open file: {}".format(file_name))
    #
    # def send_file(self, file_path, ip, src_port, dest_port):
    #     tsocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    #     tsocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    #     # tsocket.connect((self.ip, self.port))
    #     tsocket.bind(('', self.port))
    #     # tsocket.bind((self.ip, self.port))
    #     # tsocket.setblocking(0)
    #
    #     # Build packet list
    #     upackets = util.read_file(file_path, src_port, dest_port)
    #     print("Number of Packets to Send: {}\n".format(len(upackets)))
    #
    #     # packet list index number
    #     upacket_seq_num = 0
    #
    #     # number to keep track of the number of packets sent out that need acknowledgment
    #     upacket_ack_count = 0
    #
    #     while upacket_seq_num < len(upackets):
    #
    #         # if the previous packet was acknowledged, then this if will get executed
    #         # Can we send a packet, do we need to send pkt
    #         if upacket_ack_count < 1 and (upacket_ack_count + upacket_seq_num) < len(upackets):
    #             tsocket.sendto(upackets[upacket_seq_num + upacket_ack_count], (ip, dest_port))
    #             print("CLIENT: Sent packet to: {} : {}".format(ip, str(dest_port)))
    #             upacket_ack_count += 1
    #             continue
    #
    #         # if we haven't gotten an acknowledgment from the server on the
    #         # last packet we've sent then the above if won't be executed, which means that we need
    #         # to listen for an acknowledgment of the sequence number of the last packet
    #         else:
    #             try:
    #                 # Listen for ACKs
    #                 ready = select.select([tsocket], [], [], util.packet_transfer_timeout)
    #
    #                 if ready[0]:
    #                     upacket_recv, sconnection = tsocket.recvfrom(util.udp_mtu_size)
    #                     print("CLIENT: Packet received from: {}\n".format(sconnection))
    #
    #                 else:
    #                     # no ACK received before timeout
    #                     print("CLIENT: No packet received before timeout: {} - seq_num: {}\n".format(
    #                         util.packet_transfer_timeout, upacket_seq_num))
    #                     upacket_ack_count = 0
    #                     continue
    #
    #                 # unpack packet
    #                 upacket_ack_seqnum = util.unpack_ack(upacket_recv)
    #
    #                 # If this is the pkt you're looking for
    #                 # the packet's sequence number is the acknowledgment
    #                 if upacket_ack_seqnum == upacket_seq_num:
    #                     # increment the sequence number to go to send the next packet in the packet list
    #                     upacket_seq_num += 1
    #
    #                     # decrement the unacknowledged packet number because
    #                     # we've received the correct sequence number
    #                     upacket_ack_count -= 1
    #                     print("CLIENT: upacket_seq_num updated: {} - unacked updated: {}\n".format(upacket_seq_num, upacket_ack_count))
    #
    #                 else:
    #                     print("CLIENT: Out of order packet. expected: {} - received: {}\n".format(upacket_seq_num, upacket_ack_seqnum))
    #                     upacket_ack_count = 0
    #                     continue
    #
    #             except socket.error as socerr:
    #                 print("Client: Socket error: {}".format(socerr))
    #                 continue
    #
    #             except KeyboardInterrupt:
    #                 print("\nClient: Shutting down")
    #                 tsocket.close()
    #                 return
    #
    #     # send final packet to let receiver know all packets have been sent
    #     confirm_packet = util.pack_struct(0, 0, -1, b"EOF")
    #     tsocket.sendto(confirm_packet, (ip, dest_port))
    #     # Close server connection and exit successfully
    #     print("CLIENT: File Transferred Successfully")
    #     tsocket.close()

    """
    Method to send a list of files in a directory of the client's choosing to the server
    Only sends a list of files if the provided directorypath is valid and has at least 1 file in the directory
    """
    def update(self, ip, port, directorypath="."):
        # make sure that the given path exists
        if os.path.exists(directorypath):
            # list of filepaths
            filepath_list = []

            # get the names of files in the directory
            directory_file_names = os.listdir(path=directorypath)

            # if each file in the list is a file and not a folder,
            # get the full path to the file and add it to the filepath list
            for filename in directory_file_names:
                file_path = os.path.abspath(filename)

                if os.path.isfile(file_path):
                    filepath_list.append(file_path)

            # if the list is not empty, then send the list to the server
            if len(filepath_list) > 0:
                print("Preparing to Send Files to Server")

                try:
                    mtu = 1024
                    # create a TCP socket to communicate with the server
                    tsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

                    # establish a connection to the server
                    tsocket.connect((ip, port))

                    # get the list as a string
                    # files_str = str(filepath_list)

                    # send server update dir command
                    print("Sending update command")
                    tsocket.send(bytes("update", 'utf8'))

                    # waiting for resp
                    r = tsocket.recv(mtu)
                    print(r.decode('utf8'))

                    # setup json stuff
                    ip_port = "{}:{}".format(self.ip, self.port)
                    json_obj = {
                        "loc": ip_port,
                        "files": filepath_list
                        # ip_port: filepath_list
                    }

                    json_obj_str = json.dumps(json_obj)

                    seq_num = 0
                    upackets = []

                    sent = 0
                    to_send = min(mtu - util.upacket_header_size, len(json_obj_str) - sent)

                    while to_send > 0:
                        upacket = util.pack_struct(self.port, port, seq_num, bytes(json_obj_str[sent:sent + to_send], 'utf8'))
                        upackets.append(upacket)
                        sent += to_send
                        to_send = min(mtu - util.upacket_header_size, len(json_obj_str) - sent)
                        seq_num += 1

                    upackets_sent = 0
                    while upackets_sent < len(upackets):
                        bytes_sent = tsocket.send(upackets[upackets_sent])
                        print("File List Sent to Server - Sent: {} bytes".format(bytes_sent))
                        upackets_sent += 1

                    # send final packet to let receiver know all packets have been sent
                    confirm_packet = util.pack_struct(0, 0, -1, b"EOF")
                    tsocket.send(confirm_packet)
                    # print(json_obj_str)

                    # obj_from_json = json.loads(json_obj_str)
                    #
                    # for o in obj_from_json:
                    #     print(o)

                    # print(obj_from_json)

                    # send the list to the server (needs to be in bytes as of Python 3.x)
                    # bytes_sent = tsocket.send(bytes(json_obj_str, 'utf8'))
                    # bytes_sent = tsocket.send(bytes(files_str, "utf8"))

                    # echo the number of bytes sent to the server
                    # print("File List Sent to Server - Sent: {} bytes".format(bytes_sent))

                    # get the server's handshake if needed
                    # response = tsocket.recv(1024)
                    # print("Server Response: {}".format(response.decode("utf8")))

                # catch any exceptions that may occur
                except() as e:
                    print(e)
            else:
                print("Files Not Sent, No Files in Directory")
        else:
            print("Path Provided is Invalid, Please Correct Path")


if __name__ == '__main__':
    if len(sys.argv) == 1:
        print("Usage of file:")
        print("Use 1: python netclient.py <port>")
        print("Use 2 ('l' for localip, custom for arg): python netclient.py <ip = 'l' | custom> <port>")
        print("Use 3 ('s' = slow, 'n' = normal): python netclient.py <ip> <port> <mode = 's'|'n'>")

    elif len(sys.argv) == 2:
        c = Client(name=str(uuid.uuid1()), ip=None, udp_port=int(sys.argv[-1]))

    elif len(sys.argv) == 3:

        ip = ""
        if sys.argv[1] == "l":
            ip = None
        else:
            ip = sys.argv[1]

        c = Client(name=str(uuid.uuid1()), ip=ip, udp_port=int(sys.argv[2]))

    elif len(sys.argv) == 4:
        if sys.argv[-1] == "s" or sys.argv[-1] == "n":

            ip = None
            if not sys.argv[1] == "l":
                ip = sys.argv[1]

            mode = False
            if sys.argv[-1] == "s":
                mode = True

            c = Client(name=str(uuid.uuid1()), ip=ip, udp_port=int(sys.argv[2]), lmode=mode)
        else:
            print("Wrong format for 3 param mode")
