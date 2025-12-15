import socket

resolved_ip = "" 

while not resolved_ip:
    a = input("Enter the IP address or hostname to scan (e.g., 192.168.1.1 or google.com): ").strip()
    
    try:
        resolved_ip = socket.gethostbyname(a)
        print(f"Target resolved to IP: {resolved_ip}")
        
    except socket.gaierror:
        print("Error: Could not resolve that hostname or IP address. Please check your input.")

validated_ports = []
is_input_valid = False

while not is_input_valid:
    b = input("Enter port(s) (e.g., 80, 22 443, or 25-35): ").strip()
    if not b:
        print("Input cannot be empty.")
        continue
        
    print("The port(s) being checked: ", b)

    input_tokens = b.split()
    
    # 🌟 FIX 1: Use a set to automatically handle unique ports
    unique_ports_set = set()
    ports_are_valid = True
    
    for token in input_tokens:
        
        if '-' in token:
            try:
                start, end = map(int, token.split('-'))
                
                if start <= end and 0 < start <= 65535 and 0 < end <= 65535:
                    # FIX 2: Add all ports in the range to the set
                    unique_ports_set.update(range(start, end + 1))
                else:
                    print(f"Invalid Range: {token} is outside the valid range (1-65535) or start > end.")
                    ports_are_valid = False
                    break
                    
            except ValueError:
                print(f"Error: Invalid range format '{token}'. Must be two numbers separated by a hyphen.")
                ports_are_valid = False
                break
                
        else:
            try:
                port = int(token)
                if 0 < port <= 65535:
                    # FIX 2: Add the single port to the set
                    unique_ports_set.add(port)
                else:
                    print(f"Invalid Port: {port} is outside the valid range (1-65535).")
                    ports_are_valid = False
                    break
                    
            except ValueError:
                print(f"Error: Invalid port number '{token}'. Must be an integer.")
                ports_are_valid = False
                break
                
    if ports_are_valid:
        # FIX 3: Convert the set to a list and sort it before scanning
        validated_ports = sorted(list(unique_ports_set))
        is_input_valid = True
    else:
        # If input was invalid, clear the set before repeating the loop
        unique_ports_set.clear()
        pass

print(f"\nStarting scan on {resolved_ip} for {len(validated_ports)} unique port(s)...")

for port in validated_ports:
    soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    soc.settimeout(0.4)

    targetadd = (resolved_ip, port)

    result = soc.connect_ex(targetadd)
    
    soc.close()

    if result == 0:
        print(f"Port {port}: Connection is OPEN")
    else:
        print(f"Port {port}: Connection is closed or filtered")