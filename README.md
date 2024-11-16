### IoT Security Scanner for OWASP Compliance

#### Introduction
The IoT Security Scanner is a tool developed to scan IoT devices for compliance with OWASP IoT Top Ten security standards. The tool identifies known vulnerabilities and provides specific recommendations to enhance the security of IoT devices, helping organizations proactively secure their networked environments.

#### Features
- **Open Port Scanning**: Uses Nmap to detect open ports and services running on the target IoT device.
- **Weak Password Detection**: Checks for default or weak passwords commonly used on IoT devices.
- **OWASP IoT Top Ten Compliance**: Maps identified vulnerabilities to the OWASP IoT Top Ten standards.
- **Recommendations**: Provides specific security recommendations based on the detected vulnerabilities.
- **Logging**: Logs all scanning activities and results for record-keeping and analysis.

#### Usage Instructions
1. **Setup Dependencies**: Install necessary Python packages using `pip`.
    ```sh
    pip install python-nmap requests
    ```
2. **Run the Scanner**: Use the following command to start the scanner.
    ```sh
    python iot_security_scanner.py
    ```
3. **Provide Target IP**: Enter the IP address of the IoT device you want to scan.

#### Prerequisites
- **Python 3.6 or above**: Ensure you have Python installed on your system.
- **Nmap**: Install Nmap (`sudo apt-get install nmap` or similar) and ensure it is available in your system's PATH.
- **Network Access**: Ensure that the target IoT device is accessible from the network where the scanner is being run.

#### How It Works
1. **Port Scanning**: The scanner uses Nmap to identify open ports and detect potentially insecure services like Telnet and FTP.
2. **Password Testing**: Attempts to identify weak or default passwords through a basic authentication test.
3. **OWASP Mapping**: Detected issues are mapped to the OWASP IoT Top Ten, and recommendations are provided to improve compliance.
4. **Logging**: All scan activities are logged in `iot_security_scanner.log` for future reference.

#### Implementation Steps
1. **Clone Repository**: Clone this repository from GitHub.
2. **Install Dependencies**: Use `pip install -r requirements.txt` to install all necessary dependencies.
3. **Run the Tool**: Execute `python iot_security_scanner.py` to scan a device.

#### Contributing
If you find bugs or have suggestions for improvements, feel free to contribute by opening an issue or making a pull request.

#### License
This project is open-source and licensed under the MIT License.

#### Disclaimer
This tool is intended for educational purposes only. Users are responsible for ensuring they comply with applicable laws and regulations before using the scanner on IoT devices.
