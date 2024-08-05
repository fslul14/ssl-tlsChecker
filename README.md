# SSL/TLS Checker

## Overview

The SSL/TLS Checker is a Python tool designed to analyze the SSL/TLS configuration of a server. It checks the server's SSL/TLS certificate, supported protocols and cipher suites, deprecated protocols, and the presence of the HTTP Strict Transport Security (HSTS) header.

## Features

- Fetch and display SSL/TLS certificate information
- Check supported TLS protocols and cipher suites
- Identify deprecated SSL/TLS protocols
- Check for the presence of the HSTS header

## Installation

### Prerequisites

Ensure you have Python 3.7 or higher installed on your system. You also need to install the required Python packages.

### Dependencies

- `requests`
- `pyOpenSSL`
- `tabulate`

You can install the dependencies using `pip`:

```bash
pip install requests pyOpenSSL tabulate
```
### Usage
```bash
python check.py
```

### License

Feel free to customize it further if needed!
