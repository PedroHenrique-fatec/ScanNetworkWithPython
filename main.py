# import nmap
import nmap # type: ignore

# function that do the scanning the host, the protocols, the ports, the services.
def scan_target(ip):
    # Inicilization of the class PortScanner from the nmap
    scanner = nmap.PortScanner()

    # Scanning the parameter ip
    # The arguments is '-A', '-sV', '-v'
    scanner.scan(ip, arguments='-sS -O -v --script -vuln')

    # Loop for identify each host in all hosts from the target 'ip'
    for host in scanner.all_hosts():
        print(f"Hosts on a network: {host}") # Print the identified host
        
        # Verify if exist the method 'osmatch' in the host itered
        if 'osmatch' in scanner[host]:
            # Loop for search a os (system_operational) in a 'osmatch' 
            for system_operational in scanner[host]['osmatch']:
                # Print the os itered
                print(f"System operational on this host: {system_operational['name']}")
                
        # Loop for search and identify the protocols from the host itered
        for protocol in scanner[host].all_protocols():
            print(f"Protocols on a host: {protocol}") # Print the protocol in the host itered
            
            # Loop for search and identify each port in a protocol itered
            for port in scanner[host][protocol].keys():
                # Variable that contains the state of port
                port_state = scanner[host][protocol][port]['state']
                
                # Print the port identified and its state
                print(f"Port : {port} | State of port : {port_state}")
                
                # Verify if the 'method' exists in the port itered
                if 'product' in scanner[host][protocol][port]:
                    # Variable that contains the service on the port
                    service = scanner[host][protocol][port]['product']
                    # Variable that contains the version of the service on the port
                    version = scanner[host][protocol][port].get('version')
                    # Print the service and the version of the port
                    print(f"Service on the port: {service} | Version of the service: {version}") 
                    
                if 'script' in scanner[host][protocol][port]:
                    print('Vulnerabilities found: ')
                    for script_name, script_output in scanner[host][protocol][port]['script'].items():
                        print(f"Vulnerability: {script_name} | Output: {script_output}")
                else:
                    print('No vulnerabilities found on this port')
                    
if __name__ == "__main__":
    target_ip = input("Enter the target ip address that you want to scan: ") # Input for the user insert the ip address that he / she want to scan
    scan_target(target_ip) # Define the parameter of function the user's insert 