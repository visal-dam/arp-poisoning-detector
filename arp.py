from scapy.all import *
import threading
import time

arp_table = {} # router (default)
sus = {}
mac_blacklist = []
interface = "eth0"
my_mac = get_if_hwaddr(interface)
my_ip = get_if_addr(interface)

t = "" # threading constant

print(f"Hello! My ip is: {my_ip} and mac is {my_mac}")

def show_arp_table(table, t):
    print("=== Current ARP Table ===")
    for i in table:
        print(f"{i} is at {table[i]}")

show_arp_table(arp_table, t)

def arp_handler(pkt):
        if pkt[ARP].op == 1:
            arp_request_handler(pkt)
        if pkt[ARP].op == 2:
            if pkt[ARP].psrc in sus:
                resolve_arp(pkt)
            else:
                arp_response_handler(pkt)

def arp_request_handler(pkt):
    who_ip = pkt[ARP].pdst
    if who_ip not in arp_table:
        arp_table.update({who_ip : None})
        show_arp_table(arp_table, t)
        
   
def arp_response_handler(pkt):
    this_ip = pkt[ARP].psrc # ip addr
    this_mac = pkt[ARP].hwsrc # mac addr
    
    if this_ip not in arp_table:
        arp_request_handler(pkt)
        return
    
    if arp_table[this_ip] == this_mac:
        return
    elif arp_table[this_ip] == None: # first time seen
        arp_table[this_ip] = this_mac
        threading.Thread(target=show_arp_table, args=(arp_table, t)).start()
    else:
        print(f"[?!] Change in mac address for {this_ip} from {arp_table[this_ip]} -> {this_mac}. Investigating...")
        sus.update({this_ip: this_mac})
        probe(this_ip, arp_table[this_ip])
        threading.Thread(target=timeout_resolve_arp, args=(this_ip, this_mac)).start() # start timeout check

def probe(sus_ip, known_mac): # direct probe to last known location
    ether_frame = Ether(src=my_mac,dst=known_mac)
    arp_packet = ARP(op = 1, hwsrc = my_mac, psrc = my_ip, hwdst = known_mac, pdst = sus_ip)
    
    pkt = ether_frame / arp_packet # encaps
    try:
        print(f"[*] Probing {sus_ip} at last known location {known_mac}...")
        sendp(pkt, iface=interface)
    except Exception as e:
        print(e)

def resolve_arp(pkt): # if get response -> host still active + alert + blacklist sus mac
    responded_ip = pkt[ARP].psrc
    responded_mac = pkt[ARP].hwsrc
    
    # get old sus mac
    sus_mac = sus[responded_ip] # guaranteed
    if responded_mac == arp_table[responded_ip] and responded_ip in sus: # host still active
        sus.pop(responded_ip) # no longer sus 
        # no change to arp table
        print(f"[!!] {responded_ip} is still active at {arp_table[responded_ip]}. ARP poisoning attack detected from {sus_mac}! Adding to blacklist!")
        mac_blacklist.append(sus_mac)
        threading.Thread(target=show_arp_table, args=(arp_table, t)).start()
    
def timeout_resolve_arp(this_ip, this_mac): # if no response after some time -> legit change + update table
    time.sleep(5)  
    if this_ip in sus:
        arp_table[this_ip] = this_mac # update arp table (new ip <-> mac)
        sus.pop(this_ip)
        print(f"[OK] {this_ip} has moved to {this_mac}")
        threading.Thread(target=show_arp_table, args=(arp_table, t)).start()
    

# main listener
try:
    sniff(filter="arp", prn=arp_handler, store=False, iface=interface)
except Exception as e:
    print(e)
