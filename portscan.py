import socket
import threading
from queue import Queue

# User inputs
print("Select Scan Type: \n1. Quick Scan (Common Ports)\n2. Full Scan (User-defined Range)\n3. Custom Ports")
scan_type = int(input("Enter your choice (1/2/3): "))

if scan_type == 1:
    target = input("Enter the target IP address or hostname: ")
    ports = [20, 21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 3389]  # Common ports
elif scan_type == 2:
    target = input("Enter the target IP address or hostname: ")
    start_port = int(input("Enter the starting port: "))
    end_port = int(input("Enter the ending port: "))
    ports = range(start_port, end_port + 1)
elif scan_type == 3:
    target = input("Enter the target IP address or hostname: ")
    ports = list(map(int, input("Enter a comma-separated list of ports: ").split(',')))
else:
    print("Invalid choice! Exiting.")
    exit()

# Convert hostname to IP address
target_ip = socket.gethostbyname(target)

# Thread-safe queue for ports
port_queue = Queue()
for port in ports:
    port_queue.put(port)

# Thread lock for output
print_lock = threading.Lock()

# Results list for export
scan_results = []

# Scan a single port
def scan_port(port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)  # Set timeout for connection
            if s.connect_ex((target_ip, port)) == 0:  # Port open
                try:
                    banner = s.recv(1024).decode().strip()  # Try to grab the banner
                except:
                    banner = "No banner detected"
                with print_lock:
                    print(f"[OPEN] Port {port}: {banner}")
                scan_results.append(f"Port {port} OPEN: {banner}")
            else:
                scan_results.append(f"Port {port} CLOSED")
    except Exception as e:
        pass  # Ignore errors

# Worker function for threads
def worker():
    while not port_queue.empty():
        port = port_queue.get()
        scan_port(port)
        port_queue.task_done()

# Number of threads to use
num_threads = 10
threads = []

# Start threads
for _ in range(num_threads):
    thread = threading.Thread(target=worker)
    thread.start()
    threads.append(thread)

# Wait for all threads to complete
port_queue.join()
for thread in threads:
    thread.join()

# Save results to a file
with open("results.txt", "w") as file:
    file.write("\n".join(scan_results))

print("Port scan completed! Results saved to results.txt.")
