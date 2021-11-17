import socket
from sys import version

class BaseClass:
    def ip_to_int(self,ip:str)->int:
        """ Converts an IP from string to integer form """
        o = list(map(int, ip.split('.')))
        return (16777216 * o[0]) + (65536 * o[1]) + (256 * o[2]) + o[3]
    
    def ip_to_string(self,ip:int)->str:
        """ Converts an IP from integer to string form """
        o1 = int(ipnum / 16777216) % 256
        o2 = int(ipnum / 65536) % 256
        o3 = int(ipnum / 256) % 256
        o4 = int(ipnum) % 256
        return '%(o1)s.%(o2)s.%(o3)s.%(o4)s' % locals()
    
    def mac_to_bytes(self,mac:str)->bytes:
        delimiter = ':'
        if len(mac) != 17:
            raise Exception('MAC Address Invalid Length')
        if delimiter not in mac:
            raise Exception('MAC Address should contain delimeter ":" ')
        return ("".join(mac.split(':'))).encode()

class Ip(BaseClass):
    def __init__(self,
                version:int = 4,
                ttl_length:int =5,
                type_of_service:int =252,
                total_length:int =194,
                identification:int =33683,
                flags:int =0,
                fragment_offset:int=0,
                ttl:int=247,
                protocol:int=17,
                header_checksum:int =32147,
                source_address:str = "10.65.139.49",
                destination_address:str="10.180.32.226",
                encoding:str='big') -> None:
        self.verToS  = self.get_version_bytes(version=version,total_length=ttl_length)              # Version, IHL, Type of Service | Total Length
        self.type_of_service=type_of_service.to_bytes(1,encoding)  # Differentiated Services Field
        self.total_length=total_length.to_bytes(2,encoding)
        self.identification = identification.to_bytes(2,encoding)# Identification | Flags, Fragment Offset
        self.flags = flags.to_bytes(1,encoding)# TTL, Protocol | Header Checksum
        self.fragment_offset = fragment_offset.to_bytes(2,encoding)# TTL, Protocol | Header Checksum
        self.ttl = ttl.to_bytes(1,encoding) # TTL, Protocol | Header Checksum
        self.protocol = protocol.to_bytes(1,encoding)# Source Address
        self.header_checksum = header_checksum.to_bytes(2,encoding)# b'\x7d\x93'  # Destination Address
        self.source_addr = super().ip_to_int(source_address).to_bytes(4,encoding)# b'\x0a\x41\x8b\x31'  # Destination Address
        self.destination_address = super().ip_to_int(destination_address).to_bytes(4,encoding) #b'\x0a\xb4\x20\xe2'  # Destination Address
        print("init ip")
        return
    
    def create_ip_header(self)->bytes:
        """ Creates and returns an IP Header by appending all the IP layer attributes """
        self.ip_header=b''
        print("creating ip header")
        attribute_names = [
            "verToS",
            "type_of_service",
            "total_length",
            "identification",
            "flags",
            "fragment_offset",
            "ttl",
            "protocol",
            "header_checksum",
            "source_addr",
            "destination_address"
        ]
        for attr in attribute_names:
            self.ip_header+=self.__getattribute__(attr)
        return self.ip_header
    
    def get_version_bytes(self,version,total_length):
        """ Get ip version bytes """
        if(version != 4):
            raise Exception(f"Invaid IP version provided {version}")
        return hex((version << 4) | total_length).encode()


class Tcp:
    def __init__(self,
                source_port=8000,
                destination_port=9000,
                sequence_number=23,
                acknowledgement_number=2321,
                data_offset=1,
                reserved=1,
                flags=1,
                window_size=1,
                checksum=12,
                urgent_pointer=123,
                encoding='big') -> None:
        self.source_port=source_port.to_bytes(2,encoding)
        self.destination_port=destination_port.to_bytes(2,encoding)
        return

class Udp:
    def __init__(self,
                source_port=9002,
                destination_port=10040,
                length=1240,
                checksum=0,
                encoding='big') -> None:
        print("init udp")
        self.source_port = source_port.to_bytes(2,encoding)
        self.destination_port = destination_port.to_bytes(2,encoding)
        self.length = length.to_bytes(2,encoding)
        self.checksum = checksum.to_bytes(2,encoding)
        pass

    def create_udp_header(self)->bytes:
        """ Creates and returns an IP Header by appending all the IP layer attributes """
        print("creating udp header")
        self.udp_header=b''
        attribute_names = [
            "source_port",
            "destination_port",
            "length",
            "checksum"
        ]
        for attr in attribute_names:
            self.udp_header+=self.__getattribute__(attr)
        return self.udp_header


class Ethernet(BaseClass):
    def __init__(self,
                source_mac_address:str='00:00:5e:00:53:af',
                destination_mac_address:str='00:00:5e:00:53:af',
                ethernet_type:int=2048,
                encoding:str='big') -> None:
        self.source = super().mac_to_bytes(source_mac_address)              # b'\x30\x29\x52\x36\x7b\x2c'
        self.destination = super().mac_to_bytes(destination_mac_address)    # b'\x00\x0c\x29\x88\xe5\x81'
        self.type = ethernet_type.to_bytes(2,encoding)                      # b'\x08\x00'
        return


class Packet(Udp,Ip):
    def __init__(self) -> None:
        Udp.__init__(self)
        Ip.__init__(self)
        #super(Ip).__init__()

    def create_udp_packet(self)->bytes:
        udp = super().create_udp_header()
        ip = super().create_ip_header()
        return udp + ip

def func():
    sample_packet=Packet()
    print(dir(sample_packet))
    print(sample_packet.create_udp_packet())
    s = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_UDP)
    #s = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_TCP)
    s.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL,1)
    #packet = ip_header + tcp_header
    s.sendto(sample_packet, ('10.10.10.1', 0))

if __name__=="__main__":
    func()

#s=Packet()
#s.create_ip_header()
#print(s.ip_header)