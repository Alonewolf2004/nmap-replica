import socket
import re
import time
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

def analyze_banner_for_os(banner_text):
    service_info = "Unknown Service"
    os_info = "Unknown OS"

    if "Apache" in banner_text:
        service_info = re.search(r'(Apache/[\d\.]+)', banner_text)
    elif "OpenSSH" in banner_text:
        service_info = re.search(r'(OpenSSH_[\d\.]+)', banner_text)
    elif "FTPd" in banner_text:
        service_info = re.search(r'(Pure-FTPd.*?])', banner_text)
    elif "Microsoft-IIS" in banner_text:
        service_info = re.search(r'(Microsoft-IIS/[\d\.]+)', banner_text)
    elif "nginx" in banner_text:
        service_info = re.search(r'(nginx/[\d\.]+)', banner_text)

    if service_info:
        service_info = service_info.group(1)
    else:
        service_info = banner_text.split('\n')[0].strip()

    if "OpenSSH" in banner_text or "Pure-FTPd" in banner_text or "Apache" in banner_text or "nginx" in banner_text:
        os_info = "Likely Linux/Unix"
    elif "Microsoft-IIS" in banner_text or "Windows" in banner_text:
        os_info = "Likely Windows"

    return service_info, os_info

print(f"\nStarting scan on {resolved_ip} for {len(validated_ports)} unique port(s)...")

for port in validated_ports:
    soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    soc.settimeout(0.4) 

    targetadd = (resolved_ip, port)

    result = soc.connect_ex(targetadd)
    
    if result == 0:
        banner = "N/A"
        try:
            soc.settimeout(1.5) 
            
            if port in [80, 443, 8080]:
                request = f"GET / HTTP/1.1\r\nHost: {resolved_ip}\r\n\r\n"
                soc.send(request.encode())
            
            elif port in [25, 587]:
                soc.recv(1024) 
                soc.send(f"HELO {a}\r\n".encode()) 
            
            elif port == 21:
                soc.recv(1024) 
                soc.send(b"HELP\r\n")

            data = soc.recv(2048)
            
            banner = data.decode('utf-8', errors='ignore').strip().split('\n')[0]
            
            if len(banner) > 80:
                banner = banner[:80] + "..."
                
            print(f"Port {port}: Connection is OPEN -> Banner: {banner}")

        except socket.timeout:
            print(f"Port {port}: Connection is OPEN -> Banner: Open, but no response (timeout)")
        except Exception as e:
            print(f"Port {port}: Connection is OPEN -> Banner Error: {e}")

    else:
        print(f"Port {port}: Connection is closed or filtered")
    
    soc.close()

t = time.time()
total_time = t - t
time_report = f"{total_time:.2f} seconds" 

print("\n" + "="*50)
print("             SCAN SUMMARY")
print("="*50)
print(f"Target:                {a} ({resolved_ip})")
print(f"Ports Scanned:         {len(validated_ports)}")
print(f"Total Time Elapsed:    {time_report}")
print("="*50)