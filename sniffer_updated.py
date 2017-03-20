import pcapy, socket, sys
from struct import *

def ethernet_parser(packet):
    eth_length = 14 #header length
    ip_length = 20  #header length
    total_length = eth_length+ip_length

    eth_header = unpack('!6s6sB',packet[:eth_length])#takes header - src,dest,protocol (ARP,Ipv4, Ipv6)
    eth_protocol = socket.ntohs(eth_header[2]) #converts the protocol from network to host byt order
    print "Src MAC: " +str(packet[6:12])+"\n"+"Dest MAC: " +str(packet[0:6])+"\n"+"Protocol type"+str(eth_protocol)+"\n\n\n"

    #If protocol value is 8 then it is a IP packet
    if eth_protocol==8:
        ip_header = unpack('!BBHHHBBH4s4s',packet[eth_length:eth_length+ip_length])
        ipv = ip_header[0] >> 4 #offset by 4 values to take first 4 bits
        ip_header_length = ip_header[0] & 0xF #last 8 bits
        ip_header_length = ip_header_length*4 #to get byte count
        ttl = ip_header[5]
        ip_protocol = ip_header[6]
        s_addr = socket.inet_ntoa(ip_header[8])
        d_addr = socket.inet_ntoa(ip_header[9])

        print "IP version: "+str(ipv)+"\n"+"IP Header Length: "+str(ip_header_length)+"\n"+"Time to Live: "+str(ttl)+"\n"
        print "Protocol: "+str(ip_protocol)+"\n"+"Src IP_addr: "+str(s_addr)+"\n"+"Dest IP_addr: "+str(d_addr)+"\n\n\n"

        #if protocol value is 6 then it is a TCP packet

        if ip_protocol == 6:
            tcp_header = unpack('!HHLLBBHHH',packet[total_length:total_length+20])
            source_port = tcp_header[0]
            dest_port = tcp_header[1]
            sequence = tcp_header[2]
            acknowledgement = tcp_header[3]
            tcph_length =  tcp_header[4] >> 4

            header_size = eth_length+ip_length+tcph_length*4
            data = packet[header_size:]

            print "Src Port: "+str(source_port)+"\n"+"Dest_port: "+str(dest_port)+"\n"+"Data: "+str(data)+"\n\n\n"

def main():
    devices = pcapy.findalldevs() #get all the device list
    print devices
    for device in devices:
        print device
    selection = raw_input("select the device to be monitored")
    packet = pcapy.open_live(selection,65535,1,0) # device name, max number of bytes to capture for a packet,promiscious,timeout

    while (1): #continously receive packets
        (header,data) = packet.next()
        ethernet_parser(data)




if __name__=='main':
    main()