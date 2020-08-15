# PACKET SNIFFER
import struct
from struct import *
import sys
MAX_BUFFER = 65536
import socket
import textwrap

def ethernet_frame(raw_data):
    des,src,prototype = struct.unpack('! 6s 6s H', raw_data[:14])
    des_mac = get_macaddress(des)
    src_mac = get_macaddress(src)
    proto = socket.htons(prototype)
    data = raw_data[14:]
    return des_mac, src_mac, proto, data

def get_macaddress(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    mac_addr = ':'.join(bytes_str).upper()
    return mac_addr

def ipv4_datagram(raw_data):
    version_header_length = raw_data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl , proto , src, target = struct.unpack('! 8x B B 2x 4s 4s', raw_data[:20])
    return version, header_length, ttl , proto , ipv4(src), ipv4(target), raw_data[header_length:]
    pass

def ipv4(addr):
    return'.'.join(map(str,addr))

def icmp_packet(raw_data):
    icmp_type, code, checksum = struct.unpack('! B B H', raw_data[:4])
    return icmp_type, code, checksum, raw_data[4:]

def  tcp_segment(raw_data):
    (src_port, dest_port, sequence, acknowledgement, offset_reserved_flags) = struct.unpack('! H H L L H',raw_data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    
    return src_port, dest_port, sequence, acknowledgement , flag_urg , flag_syn, flag_rst, flag_psh, flag_fin, flag_ack, raw_data[offset:]

def udp_segment (raw_data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', raw_data[:8])
    return src_port, dest_port, size, raw_data[8:]

def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])
    
def main():
    conn = socket.socket(socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(3))    
    while True:
        raw_data, addr = conn.recvfrom(MAX_BUFFER)
        eth = ethernet_frame(raw_data)
        print('\nEthernet Frame: ' )
        print('DESTINATION MAC :- ' + eth[0] + ', SOURCE MAC:- ' + eth[1] + ', PROTOCOL:- ' + str(eth[2]))
        if eth[2] == 8:
            ipv4 = ipv4_datagram(eth[3])
            print('\tIPV4 PACKETS: ')
            print('\t'+'VERSION:- ' +  str(ipv4[0]) + ', Header Length:- ' + str(ipv4[1])  + ', TTL:- '+ str(ipv4[2]) + ', PROTOCOL:- ' + str(ipv4[3]) + ', SOURCE:- ' + ipv4[4] + ', TARGET:- '+ ipv4[5])
            if ipv4[3] == 1:
                icmp = icmp_packet(ipv4[6])
                print('\t\tICMP PACKET')
                print('\t\t'+"TYPE:- " +  str(icmp[0])+ ", CODE:- " + str(icmp[1]) +  ", CHECKSUM:- " + str(icmp[2]))
                print('\t\t\tICMP DATA:')
                print(format_multi_line('\t\t\t', icmp[3]))
            if ipv4[3] == 6:
                tcp = tcp_segment(ipv4[6])
                print('\t\tTCP SEGMENT')
                print('\t\t'+"SOURCE PORT:- "+ str(tcp[0]) + ", DESTINATION PORT:- " + str(tcp[1]))
                print('\t\t'+"SEQUENCE:- " + str(tcp[2]) +  ", ACKNOWLEDGEMENT:- "+ str(tcp[3]))
                print('\t\tFLAGS')
                print('\t\t'+'URG:- ' + str(tcp[4]) + ', ACK:- ' +  str(tcp[9]) +  ', PSH:- ' + str(tcp[7]) +  ', RST:- ' + str(tcp[6])  + ', SYN:- '+ str(tcp[5]) + ', FIN:- '+ str(tcp[8]))
                print('\t\t\tTCP DATA:')
                print(format_multi_line('\t\t\t', tcp[10]))

            if ipv4[3] == 17:
                udp = udp_segment(ipv4[6])
                print("\t\tUDP SEGMENT ")
                print('\t\t'+"SOURCE_PORT:- " +  str(udp[0]) + ", DESTINATION_PORT:- " + str(udp[1]) +  ", LENGTH:- " + str(udp[2]))  
                print('\t\t\tUDP DATA:')
                print(format_multi_line('\t\t\t', udp[3]))

        else:
            print('DATA: ')
            print(raw_data)
            
main()
