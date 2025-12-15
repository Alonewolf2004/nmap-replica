import socket
import re
import time
import threading
import queue

# Global variables for thread synchronization and results
open_ports_found = 0
queue_of_ports = queue.Queue()
lock = threading.Lock()

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

# --- NEW: Multithreaded Worker Function ---
def port_scan_worker(target_ip, original_hostname):
    global open_ports_found
    
    while not queue_of_ports.empty():
        try:
            port = queue_of_ports.get_nowait()
        except queue.Empty:
            return

        soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        soc.settimeout(0.4) 
        targetadd = (target_ip, port)
        result = soc.connect_ex(targetadd)
        
        if result == 0:
            with lock:
                open_ports_found += 1 
            
            raw_banner = "N/A"
            try:
                soc.settimeout(1.5) 
                
                data_to_send = None
                if port in [80, 443, 8080]:
                    data_to_send = f"GET / HTTP/1.1\r\nHost: {target_ip}\r\n\r\n".encode()
                elif port in [25, 587]:
                    soc.recv(1024) 
                    data_to_send = f"HELO {original_hostname}\r\n".encode()
                elif port == 21:
                    soc.recv(1024) 
                    data_to_send = b"HELP\r\n"
                
                if data_to_send:
                    soc.send(data_to_send)

                data = soc.recv(4096) 
                raw_banner = data.decode('utf-8', errors='ignore')
                
                service_version, os_version = analyze_banner_for_os(raw_banner)
                
                if port in [80, 443, 8080]:
                    server_match = re.search(r'Server: (.*?)\r\n', raw_banner, re.IGNORECASE)
                    if server_match:
                        service_version = server_match.group(1).strip()
                        _, os_version = analyze_banner_for_os(service_version)

                display_banner = raw_banner.strip().split('\n')[0]
                if len(display_banner) > 80:
                    display_banner = display_banner[:80] + "..."
                
                with lock:
                    print(f"Port {port}: OPEN -> Service: {service_version} | OS: {os_version} | Banner: {display_banner}")

            except socket.timeout:
                with lock:
                    print(f"Port {port}: OPEN -> No data received (timeout)")
            except Exception as e:
                with lock:
                    print(f"Port {port}: OPEN -> Banner Error: {e}")
        else:
            with lock:
                print(f"Port {port}: closed or filtered")
        
        soc.close()
        queue_of_ports.task_done()

# --- MAIN EXECUTION ---

# --- DNS Resolution ---
resolved_ip = "" 

while not resolved_ip:
    a = input("Enter the IP address or hostname to scan (e.g., 192.168.1.1 or google.com): ").strip()
    
    try:
        resolved_ip = socket.gethostbyname(a)
        print(f"Target resolved to IP: {resolved_ip}")
        
    except socket.gaierror:
        print("Error: Could not resolve that hostname or IP address. Please check your input.")

# --- Port Validation ---
validated_ports = []
is_input_valid = False

while not is_input_valid:
    b = input("Enter port(s) (e.g., 80, 22 443, or 25-35): ").strip()
    if not b:
        print("Input cannot be empty.")
        continue
        
    print("The port(s) being checked: ", b)

    input_tokens = b.split()
    unique_ports_set = set()
    ports_are_valid = True
    
    for token in input_tokens:
        
        if '-' in token:
            try:
                start, end = map(int, token.split('-'))
                
                if start <= end and 0 < start <= 65535 and 0 < end <= 65535:
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
        validated_ports = sorted(list(unique_ports_set))
        is_input_valid = True
    else:
        unique_ports_set.clear()
        pass

# --- Threading Scan Execution ---

scan_start_time = time.time()
thread_count = 100 

print(f"\nStarting multithreaded scan on {resolved_ip} for {len(validated_ports)} unique port(s) using {thread_count} threads...")

# 1. Fill the Queue
for port in validated_ports:
    queue_of_ports.put(port)

# 2. Start Worker Threads
threads = []
for _ in range(thread_count):
    thread = threading.Thread(target=port_scan_worker, args=(resolved_ip, a))
    thread.daemon = True
    thread.start()
    threads.append(thread)

# 3. Wait for the Queue to be Empty
queue_of_ports.join()

# --- Scan Summary ---

scan_end_time = time.time()
total_time = scan_end_time - scan_start_time
time_report = f"{total_time:.2f} seconds" 

print("\n" + "="*50)
print("             SCAN SUMMARY")
print("="*50)
print(f"Target:                {a} ({resolved_ip})")
print(f"Ports Scanned:         {len(validated_ports)}")
print(f"Open Ports Found:      {open_ports_found}")
print(f"Total Time Elapsed:    {time_report}")
print("="*50)