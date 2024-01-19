DNS Honeypot

Overview

This Python script serves as a DNS honeypot, designed to attract and analyze malicious DNS traffic for research and security purposes. It handles DNS queries over UDP and TCP, implements request limiting per IP, and logs detailed query information.
Features

    UDP and TCP Support: Processes DNS queries on both protocols.
    Request Limiting: Restricts the number of requests per IP to mitigate abuse.

Requirements

    Python 3.x
    dnspython (pip install dnspython)

Customization

Adjust `MAX_REQUESTS_PER_IP` in the script to change the request limit per IP.

Disclaimer: This script is intended for research and educational purposes. It should be used responsibly in controlled environments.
