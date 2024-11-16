import nmap
import socket
import json
import requests
import logging
from pprint import pprint

# Set up logging
logging.basicConfig(filename='iot_security_scanner.log', level=logging.INFO, format='%(asctime)s %(message)s')

OWASP_TOP_TEN = [
    "Weak, Guessable, or Hardcoded Passwords",
    "Insecure Network Services",
    "Insecure Ecosystem Interfaces",
    "Lack of Secure Update Mechanism",
    "Use of Insecure or Outdated Components",
    "Insufficient Privacy Protection",
    "Insecure Data Transfer and Storage",
    "Lack of Device Management",
    "Insecure Default Settings",
    "Lack of Physical Hardening"
]

RECOMMENDATIONS = {
    "Weak, Guessable, or Hardcoded Passwords": "Use strong, unique passwords for all devices and change any default credentials.",
    "Insecure Network Services": "Disable unnecessary network services and limit network exposure.",
    "Insecure Ecosystem Interfaces": "Secure all API endpoints with authentication and encryption.",
    "Lack of Secure Update Mechanism": "Ensure that firmware updates are delivered over secure channels.",
    "Use of Insecure or Outdated Components": "Update outdated components to latest secure versions.",
    "Insufficient Privacy Protection": "Ensure that all sensitive data is encrypted and privacy controls are in place.",
    "Insecure Data Transfer and Storage": "Implement encryption for all data in transit and at rest.",
    "Lack of Device Management": "Provide a mechanism for secure remote management of devices.",
    "Insecure Default Settings": "Disable default settings and implement a least privilege approach.",
    "Lack of Physical Hardening": "Secure physical access to devices to prevent tampering."
}

# Function to scan for open ports using Nmap
def scan_device(ip_address):
    logging.info(f"Scanning IP: {ip_address}")
    nm = nmap.PortScanner()
    try:
        nm.scan(ip_address, arguments='-T4 -F')
        return nm[ip_address]
    except Exception as e:
        logging.error(f"Nmap error: {e}")
        return None

# Function to check for weak passwords
# This is a simplified example. In a real implementation, more sophisticated methods would be used.
def check_weak_password(ip_address):
    weak_passwords = ["admin", "1234", "password", "root"]
    for password in weak_passwords:
        try:
            # Assume Telnet connection for password check
            sock = socket.create_connection((ip_address, 23), timeout=5)
            sock.sendall((password + '\n').encode())
            time.sleep(2)
            response = sock.recv(1024)
            if b"Login successful" in response:
                logging.info(f"Weak password detected for {ip_address}: {password}")
                return True
        except Exception as e:
            logging.warning(f"Password check error for {ip_address}: {e}")
            continue
    return False

# Function to provide OWASP-based recommendations
def provide_recommendations(vulnerabilities):
    recs = []
    for vulnerability in vulnerabilities:
        if vulnerability in RECOMMENDATIONS:
            recs.append(RECOMMENDATIONS[vulnerability])
    return recs

# Main IoT device scan and vulnerability assessment
def scan_iot_device(ip_address):
    vulnerabilities_detected = []
    
    # Scan device for open ports and services
    scan_result = scan_device(ip_address)
    if not scan_result:
        logging.error(f"No scan results for IP: {ip_address}")
        return vulnerabilities_detected
    
    # Check open ports for insecure services (OWASP: Insecure Network Services)
    if 'tcp' in scan_result.all_protocols():
        for port in scan_result['tcp']:
            state = scan_result['tcp'][port]['state']
            if state == 'open':
                service = scan_result['tcp'][port]['name']
                logging.info(f"Open port detected: {port} - {service}")
                if service in ['telnet', 'ftp', 'http']:
                    vulnerabilities_detected.append("Insecure Network Services")
    
    # Check for weak passwords
    if check_weak_password(ip_address):
        vulnerabilities_detected.append("Weak, Guessable, or Hardcoded Passwords")
    
    # Log vulnerabilities and provide recommendations
    logging.info(f"Vulnerabilities detected for {ip_address}: {vulnerabilities_detected}")
    recommendations = provide_recommendations(vulnerabilities_detected)
    
    return vulnerabilities_detected, recommendations

if __name__ == "__main__":
    print("IoT Security Scanner for OWASP Compliance")
    target_ip = input("Enter the IP address of the IoT device to scan: ")
    vulnerabilities, recommendations = scan_iot_device(target_ip)

    if vulnerabilities:
        print("\nVulnerabilities Detected:")
        pprint(vulnerabilities)
        print("\nRecommendations to Improve Security:")
        pprint(recommendations)
    else:
        print("No vulnerabilities detected. The device seems to be secure.")
