import nmap

def nmap_scan(target):
    nm = nmap.PortScanner()
    nm.scan(hosts=target, arguments='-p 1-1024 -sV -T4')

    for host in nm.all_hosts():
        print('Host : %s (%s)' % (host, nm[host].hostname()))
        print('State : %s' % nm[host].state())

        for proto in nm[host].all_protocols():
            print('----------')
            print('Protocol : %s' % proto)

            lport = nm[host][proto].keys()
            for port in lport:
                print('port : %s\tstate : %s' % (port, nm[host][proto][port]['state']))
                print('Service : %s' % nm[host][proto][port]['name'])
                print('Version : %s' % nm[host][proto][port]['version'])

if __name__ == "__main__":
    target = input("Enter target IP address or range: ")
    nmap_scan(target)