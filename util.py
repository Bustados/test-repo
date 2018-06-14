import ctypes
import struct
import sys
import zlib


# data portion is not included in header
#   2bytes      2bytes     2bytes   4bytes    2bytes    ?bytes
# | src_port | dest_port | chksum | seq_num | pkt_size | data |
upacket_ack_format = "i"
upacket_header_format = "3H{}H".format(upacket_ack_format)

# header length in bytes
upacket_header_size = struct.calcsize(upacket_header_format)

# file read size
# upacket_read_size = 1024*2
upacket_read_size = 81
# upacket_read_size = 65

# max udp send rate in bytes
udp_mtu_size = 128
# udp_mtu_size = 4096

# amount of time in seconds for packet loss detection
packet_transfer_timeout = 4

cipher_blocksize = 32



def checksum2(data):
    return (ctypes.c_ushort(int(zlib.crc32(data) % 2**32))).value


def read_file(file_path, sport, dport):
    file_upackets = []

    seq_num = 0

    try:
        fd = open(file_path, 'rb')

        while True:
            file_bytes_read = fd.read(upacket_read_size)

            if not file_bytes_read:
                break

            # print(seq_num)
            # print(file_bytes_read)

            upkt = pack_struct(sport, dport, seq_num, file_bytes_read)

            # print(upkt)

            file_upackets.append(upkt)
            seq_num += 1

        fd.close()

        # print(seq_num)

    except() as e:
        print("Failed to open file: ", file_path)
        sys.exit(-1)

    return file_upackets


def pack_struct(sport, dport, seqnum, data):
    data_size = len(data)
    # data_size = data.__sizeof__()

    # print(data_size)

    data_format = "{}s".format(data_size)

    upstruct_format = upacket_header_format + data_format

    # print(upstruct_format)

    upacket_size = struct.calcsize(upstruct_format)

    # print(upacket_size)

    upacket_data_bytes = data

    upacket_data_struct = struct.pack(data_format, upacket_data_bytes)

    # print(upacket_data_struct)

    upacket_chksum = checksum2(upacket_data_struct)

    # print(upacket_chksum)

    # chksum = checksum(upacket_data_bytes.encode('utf8'))
    # upacket_data_bytes = bytes(data, 'utf-8')
    #
    # print(upacket_data_bytes)

    upacket_struct = struct.pack(upstruct_format, sport, dport, upacket_chksum, seqnum, upacket_size, upacket_data_bytes)
    # upacket_struct = struct.pack(upstruct_format, sport, dport, chksum, seqnum, upacket_size, data)

    # print(upacket_struct)

    return upacket_struct


def unpack_struct(upacket):
    unpack_header = struct.unpack_from(upacket_header_format, upacket[:14])

    unpack_packet_size = unpack_header[-1]

    unpack_data_size = unpack_packet_size - upacket_header_size

    unpack_packet = struct.unpack("{}{}s".format(upacket_header_format,  unpack_data_size), upacket)

    return unpack_packet

    # print(unpack_packet)


def pack_ack(upacket):
    return struct.pack(upacket_ack_format, upacket[-3])


def unpack_ack(ack_bytes):
    return struct.unpack(upacket_ack_format, ack_bytes)[0]
