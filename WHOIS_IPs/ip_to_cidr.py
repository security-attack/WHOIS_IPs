#Security-Attack
#Version 1.0.1
import os
import ipaddress


All_IP_bUFFER = []


def IP_Whois(ip):
    global All_IP_bUFFER
    
    print("-" * 20)
    print("[{}/{}] --> {}".format(len(list_ip),i,list_ip[i]))
    save_file = open("whois_ips.txt","a+")
    #Check Ip in DB
    if ip in All_IP_bUFFER:
        #print("[+] Find IP in DB")
        pass
    else:
        #Clear Buffer
        All_IP_bUFFER = []

        save_file.write(str("-" * 20 + "\n"))
        #print("-" * 20)
        save_file.write(str("[+] IP -> " + ip + "\n"))
        #print("[+] IP -> ",ip)
        
        whois = os.popen("whois {} | grep 'NetRange:\|NetName:\|CIDR:\|Organization:\|OrgName:\|inetnum:\|owner:\|descr:'".format(ip)).read()
        save_file.write(str(whois + "\n"))
        print(whois)
        #Extract Fields
        whois_Extcat_Info = whois.split("\n")
        
        '''
        #1
        inetnum:      143.0.0.0 - 143.255.255.255
        NetRange:       143.166.0.0 - 143.166.255.255    CIDR[1]
        CIDR:           143.166.0.0/16
        NetName:        DELL
        Organization:   Dell, Inc. (DCC-25)
        OrgName:        Dell, Inc.
        '''
        if "CIDR:" in str(whois_Extcat_Info):
            cidr = ""
            for x0 in range(0,len(whois_Extcat_Info)):
                cidr_finder = str(whois_Extcat_Info[x0]).find("CIDR:")
                if cidr_finder == -1:
                    pass
                elif not(cidr_finder == -1):
                    cidr = str(whois_Extcat_Info[x0]).replace("CIDR:","").replace(" ","")       
                    
            #cidr = str(whois_Extcat_Info[2]).replace("CIDR:","").replace(" ","")
            #print("CIDR => ",cidr)
            cidr_s = cidr.split(",")
            #print("CIDR => ",str(cidr_s))
            for x in range(0,len(cidr_s)):
                print("Selected CIDR  -> ",cidr_s[x])
                ips = [str(ip) for ip in ipaddress.IPv4Network(cidr_s[x])]
                
                #Append IPs To List
                round = 0
                while round < len(ips):
                    All_IP_bUFFER.append(ips[round])
                    round += 1
                
                x += 1
            '''
            #2
            201.130.47.235
            inetnum:      201.0.0.0 - 201.255.255.255
            inetnum:     201.130.32.0/20                   CIDR[1]
            owner:       AT&T COMUNICACIONES DIGITALES S DE RL
            #3
            202.135.111.98
            inetnum:      202.0.0.0 - 202.255.255.255
            inetnum:        202.135.111.0 - 202.135.111.255
            '''
        elif "inetnum:" in str(whois_Extcat_Info):
            ip_range_type = str(whois_Extcat_Info).find("")
            cidr = 0
            if ip_range_type == -1:
                print("inetnum => ",whois_Extcat_Info[0].replace("inetnum:","").replace(" ",""))
                start_range = whois_Extcat_Info[0].replace("inetnum:","").replace(" ","").split("-")[0]
                end_range = whois_Extcat_Info[0].replace("inetnum:","").replace(" ","").split("-")[1]
                
                print("Start => ",start_range)
                print("End => ",end_range)
                
                startip = ipaddress.IPv4Address(start_range)
                endip = ipaddress.IPv4Address(end_range)
                cidr = [ipaddr for ipaddr in ipaddress.summarize_address_range(startip, endip)]
                print("CIDR => ",cidr[0])
            elif not(ip_range_type == -1):
                cidr = ""
                for x2 in range(0,len(whois_Extcat_Info)):
                    cidr_finder = str(whois_Extcat_Info[x2]).find("inetnum:")
                    if cidr_finder == -1:
                        pass
                    elif not(cidr_finder == -1):
                        cidr = str(whois_Extcat_Info[x2]).replace("inetnum:","").replace(" ","")  
                
                start_range = cidr.replace("inetnum:","").replace(" ","").split("-")[0]
                end_range = cidr.replace("inetnum:","").replace(" ","").split("-")[1]
                print("Start => ",start_range)
                print("End => ",end_range)
                
                startip = ipaddress.IPv4Address(start_range)
                endip = ipaddress.IPv4Address(end_range)
                cidr = [ipaddr for ipaddr in ipaddress.summarize_address_range(startip, endip)]
                print("CIDR => ",str(cidr[0]))
                cidr_to_save = str(cidr[0])
                save_file.write(str("CIDR: " + cidr_to_save + "\n"))
                
                #cidr = str(whois_Extcat_Info[1]).replace("inetnum:","").replace(" ","")
                print("Selected CIDR(Inet)=> ",cidr)
                cidr_s = list(cidr)
                
            #print("CIDR => ",str(cidr_s))
            for x in range(0,len(cidr_s)):
                print("Selected Inetnumber => ",str(cidr_s[x]))
                #print("Selected CIDR  -> ",cidr_s[x])
                ips = [str(ip) for ip in ipaddress.IPv4Network(cidr_s[x])]
                
                #Append IPs To List
                round = 0
                while round < len(ips):
                    All_IP_bUFFER.append(ips[round])
                    round += 1
                
                x += 1

        
                #print("IPs in DB -> ",len(All_IP_bUFFER))
    save_file.close()

ip_list_file = open("ips.txt","r")
list_ip = ip_list_file.readlines()

for i in range(0,len(list_ip)):
    IP_Whois(str(list_ip[i]).replace("\n",""))
    i += 1# 
