import socket, struct, argparse
from dataclasses import dataclass

@dataclass
class DNSMessage:
    id: int
    qr: int
    opcode: int
    aa: int
    tc: int
    rd: int
    ra: int
    z: int
    rcode: int
    qdcount: int
    ancount: int
    nscount: int
    arcount: int
    questions: str
    answers: str

def pack_dns_message(message: DNSMessage) -> bytes:
    flags = (
        (message.qr << 15)
        | (message.opcode << 11)
        | (message.aa << 10)
        | (message.tc << 9)
        | (message.rd << 8)
        | (message.ra << 7)
        | (message.z << 4)
        | message.rcode
    )
    return struct.pack(f'>HHHHHH{len(message.questions)}s{len(message.answers)}s', message.id, flags, message.qdcount, message.ancount, message.nscount, message.arcount, message.questions, message.answers)
    
def isPointer(buf):
    return (buf[0]) >> 6 == 0b11

def encodeDomain(domain):
    encoded = b''
    # Split the domain name on "."
    words = domain.split(".")

    # Iterate over each word
    for word in words:
        encoded += struct.pack(f"!B{len(word)}s", len(word), word.encode('utf-8'))  
    
    return encoded + b'\x00'



def getDomain(buf, i):
    """Given full buffer and index i, return domain name  starting at index i"""
    decoded_domain = ""
    while i < len(buf):
        if isPointer(buf[i:]):
            pointer = (buf[i] & 0b00111111 << 8) | buf[i+1]
            name, _, TypeClass = getDomain(buf, pointer)
            decoded_domain += name
            #i += 6
            return decoded_domain, i + 6, buf[i+2:i+6]
        label_length = buf[i]
        i += 1

        if label_length == 0:
            return decoded_domain.rstrip("."), i + 4, buf[i:i+4]
        decoded_label = buf[i:i + label_length].decode('utf-8')
        decoded_domain += decoded_label + "."
        i += label_length
    return decoded_domain.rstrip("."), i + 4, buf[i:i+4]


# We get full dns-packet and number of Questions; return all domain names in list
def getQuestions(buf, count):
    q_list = []
    flaglist = []
    index = 12
    for i in range (count):
        name = ""
        TypeClass = b''
        if isPointer(buf[index:]):
            pointer = (buf[index] & 0b00111111 << 8) | buf[index+1]
            #print("POINTER", pointer)
            name, _, TypeClass = getDomain(buf, pointer)
            #print("NAME", name)
            index += 5
        else:
            name, index, TypeClass = getDomain(buf, index)
        #print("name is", name)    
        q_list = q_list + [name]
        flaglist = flaglist + [TypeClass]
    return q_list, flaglist


# given buf return answer section, there is always 1 question, 1 answer
def getAnswer(buf):
    #print("answer len is: ", len(buf))
    index = 12
    while buf[index] != 0:
        index += buf[index] +1
    return buf[(index + 5):]

def main():
    print("Logs from your program will appear here!")
    
    # Get resolver's IP
    parser = argparse.ArgumentParser()
    parser.add_argument('--resolver', help='Specify the resolver address')
    resolver_address = parser.parse_args().resolver
    ip, port = resolver_address.split(':')
    print(ip, port)
    forward_addr = (ip, int(port))
    
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))
    while True:
        try:
             buf, source = udp_socket.recvfrom(512)
             print("BUFF RECIEVE", buf)
             
             '''
             udp_socket.sendto(buf, forward_addr)
             resp_buf, forward_addr = udp_socket.recvfrom(512)
             print("resolver responded with answer: ", resp_buf)
             getAnswerOffset(resp_buf)
             '''
             #parse header
             ID = struct.unpack('!H', buf[:2])[0]
             byte = struct.unpack('!B', buf[2:3])[0]
             opcode = (byte >> 3) & 0b1111
             rd = byte & 0b1
             rcode = 4
             rcode = 0 if opcode == 0 else rcode
             QDcount = int.from_bytes(buf[4:6], byteorder='big')
              
             #parse query
             domains, flags = getQuestions(buf, QDcount)
             print("HEREE")
             
             print("flags", flags)
             '''TODO: for each domain make a DNS Message and forward it to resolver'''
             
             '''TODO: get answers and concat them; return it to sender'''
             
             
             #Create Question
             Type = (1).to_bytes(2, byteorder='big')

             # Record class is "IN", represented as 0x0001 in 2-byte integer format
             Class = (1).to_bytes(2, byteorder='big')  
             
             Questions = b''
             RR = b''
             
             '''answer constants'''
             Answer_type = struct.pack('!H', 1)
             Answer_class = struct.pack('!H', 1)
             Answer_TTL = struct.pack('!I', 60)
             Answer_length = struct.pack('>H', 4)
             Answer_data = struct.pack('!BBBB', 8, 8, 8, 8)
             
             
             # Handle sending questions to forwarder one by one.
             for i in range(QDcount): #domains[i]  flags[i]
                 Name = encodeDomain(domains[i])
                 Question = Name + flags[i]  # make question
                 Questions += Question # Get all questions in one byte string for final message
                 
                 forwarded_msg = answer_msg = DNSMessage(id=ID, qr=0, opcode=opcode, aa=0, tc=0, rd=rd, ra=0, z=0, rcode=rcode, qdcount=1, ancount=0, nscount=0, arcount=0, questions=Question, answers=b'')
                 frwd = pack_dns_message(forwarded_msg)
                 
                 #print("sending to forwarder", frwd)
                 udp_socket.sendto(frwd, forward_addr)
                 
                 new_buf, new_source = udp_socket.recvfrom(512)
                 print("response from big daddy forwarder:", new_buf)
                 
                 if QDcount == 1:
                     ## idgaf directly send this shit back
                     udp_socket.sendto(new_buf, source)
                     break
                 else:
                     # update RR
                     RR += getAnswer(new_buf)
                     print("getting answer from forwarder:", getAnswer(new_buf))
             
             
             answer_msg = DNSMessage(id=ID, qr=1, opcode=opcode, aa=0, tc=0, rd=rd, ra=0, z=0, rcode=rcode, qdcount=QDcount, ancount=QDcount, nscount=0, arcount=0, questions=Questions, answers=RR)
             
             response = pack_dns_message(answer_msg)
             udp_socket.sendto(response, source)
             
             
             
             # Send final Request
             # change handling of answers######
             '''
             answer_msg = DNSMessage(id=ID, qr=1, opcode=opcode, aa=0, tc=0, rd=rd, ra=0, z=0, rcode=rcode, qdcount=QDcount, ancount=0, nscount=0, arcount=0, questions=b'', answers=b'')
             
             response = pack_dns_message(answer_msg)
             udp_socket.sendto(response, source)
             print("end") '''
        except Exception as e:
             print(f"Error receiving data: {e}")
             break


if __name__ == "__main__":
    main()
'''
#Create Question
             Type = (1).to_bytes(2, byteorder='big')

             # Record class is "IN", represented as 0x0001 in 2-byte integer format
             Class = (1).to_bytes(2, byteorder='big')  
             
             Questions = b''
             RR = b''
             
             #answer constants
             Answer_type = struct.pack('!H', 1)
             Answer_class = struct.pack('!H', 1)
             Answer_TTL = struct.pack('!I', 60)
             Answer_length = struct.pack('>H', 4)
             Answer_data = struct.pack('!BBBB', 8, 8, 8, 8)
             

             for domain in domains:
                 Name = encodeDomain(domain)
                 Question = Name + Type + Class  # make question
                 Questions += Question # I will need this for later
                 
                 Answer_name = encodeDomain(domain)
                 RR = Answer_name + Answer_type + Answer_class + Answer_TTL + Answer_length + Answer_data
                 RR = RR+RR
             
             
             # Send final Request
             # change handling of answers######
             answer_msg = DNSMessage(id=ID, qr=1, opcode=opcode, aa=0, tc=0, rd=rd, ra=0, z=0, rcode=rcode, qdcount=QDcount, ancount=QDcount, nscount=0, arcount=0, questions=Questions, answers=RR)
             
             response = pack_dns_message(answer_msg)
             udp_socket.sendto(response, source)
        except Exception as e:
             print(f"Error receiving data: {e}")
             break

'''
