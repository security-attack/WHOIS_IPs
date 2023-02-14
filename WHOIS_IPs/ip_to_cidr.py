#!usr/bin/env python
#www.Security-Attack.net
#Version 2.0.1

# bulk whois with socket programing and whois.cymru.com
import socket
import argparse

def main():
    parser = argparse.ArgumentParser(description='Bulk whois')
    parser.add_argument('-f', '--file', help='File with ips')
    args = parser.parse_args()
    if args.file:
        with open(args.file, 'r') as f:
            ips = f.read()
            ips = "begin\nverbose\n" + ips + "end"
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(('whois.cymru.com', 43))
            s.send(ips.encode('utf-8'))
            datalist = b''
            while True:
                part = s.recv(4096)
                datalist += part
                if len(part) < 4096:
                    break
            data = datalist.decode('utf-8').splitlines()
            for ipinfo in data[1:]:
                print(f"""
asn: {ipinfo.split('|')[0].strip()}
ip: {ipinfo.split('|')[1].strip()}
cidr: {ipinfo.split('|')[2].strip()}
country: {ipinfo.split('|')[3].strip()}
registry: {ipinfo.split('|')[4].strip()}
AS Name: {ipinfo.split('|')[-1].strip()}
""")

            s.close()
    else:
        parser.print_help()

if __name__ == '__main__':
    main()
