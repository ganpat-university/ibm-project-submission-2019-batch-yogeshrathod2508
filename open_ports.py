import socket
import threading
import time
ports = []
# function to scan ports and see which ports are open
def scan_port(port):
# we will check port of localhost
    host = "localhost"
    host_ip = socket.gethostbyname(host)
    
    # print("host_ip = {}".format(host_ip))
    status = False
    # create instance of socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # connecting the host ip address and port
    try:
        s.connect((host_ip, port))
        status = True
    except:
        status = False

    if status:
        try:
            ports.append([port,socket.getservbyport(port, "tcp")])
        except:
            try:
                #print("port {} => {}".format(port,socket.getservbyport(port, "udp")))
                ports.append([port,socket.getservbyport(port, "udp")])
            except:
                #print("port {} is open".format(port))
                ports.append([port,""])
    

start_time = time.time()

for i in range(0, 1025):
    thread = threading.Thread(target=scan_port, args=[i])
    thread.start()
    
print(ports[1][0])
end_time = time.time()
print("To all scan all ports it took {} seconds".format(end_time-start_time))