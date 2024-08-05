import ssl
import socket
import OpenSSL
from datetime import datetime
from tabulate import tabulate
import requests
import warnings
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Suppress InsecureRequestWarning if needed (not recommended for production use)
warnings.simplefilter('ignore', InsecureRequestWarning)

def get_certificate_info(hostname, port=443):
    """
    Fetch the SSL/TLS certificate from the server.

    Args:
        hostname (str): The hostname of the server.
        port (int): The port number, default is 443 for HTTPS.

    Returns:
        OpenSSL.crypto.X509: The certificate object.
    """
    context = ssl.create_default_context()
    with socket.create_connection((hostname, port)) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            cert_bin = ssock.getpeercert(binary_form=True)
            cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert_bin)
            return cert

def format_certificate_info(cert):
    """
    Format the certificate information into a readable format.

    Args:
        cert (OpenSSL.crypto.X509): The certificate object.

    Returns:
        list: A list of certificate information formatted for tabulate.
    """
    subject = cert.get_subject()
    issuer = cert.get_issuer()
    info = [
        ["Subject", f"{subject.CN} ({subject.O})"],
        ["Issuer", f"{issuer.CN} ({issuer.O})"],
        ["Serial Number", cert.get_serial_number()],
        ["Valid From", datetime.strptime(cert.get_notBefore().decode('ascii'), '%Y%m%d%H%M%SZ')],
        ["Valid Until", datetime.strptime(cert.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ')],
        ["Version", cert.get_version()],
        ["Public Key", cert.get_pubkey().type()],
        ["Signature Algorithm", cert.get_signature_algorithm().decode()]
    ]
    return info

def check_tls_config(hostname, port=443):
    """
    Check supported TLS protocols and cipher suites.

    Args:
        hostname (str): The hostname of the server.
        port (int): The port number, default is 443 for HTTPS.

    Returns:
        tuple: A tuple containing lists of supported protocols and cipher suites.
    """
    context = ssl.create_default_context()
    supported_protocols = []
    supported_ciphers = []

    try:
        with socket.create_connection((hostname, port)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                # Detect the TLS protocol version used
                protocol_version = ssock.version()
                if protocol_version:
                    supported_protocols.append(protocol_version)
                
                # Get the list of supported ciphers
                ciphers = ssock.cipher()
                if ciphers:
                    supported_ciphers.append([ciphers[0][0], ciphers[0][1]])
    except (ssl.SSLError, OSError) as e:
        print(f"SSL/TLS Error: {e}")
    
    return supported_protocols, supported_ciphers

def check_deprecated_protocols(hostname, port=443):
    """
    Check for deprecated SSL/TLS protocols.

    Args:
        hostname (str): The hostname of the server.
        port (int): The port number, default is 443 for HTTPS.

    Returns:
        list: A list of deprecated protocols that are supported by the server.
    """
    deprecated_protocols = ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"]
    results = []

    for protocol in deprecated_protocols:
        try:
            context = ssl.create_default_context()
            context.options |= getattr(ssl, f"PROTOCOL_{protocol}")
            with socket.create_connection((hostname, port)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    if ssock.version() == protocol:
                        results.append(f"Deprecated protocol {protocol} supported")
        except (ssl.SSLError, AttributeError, OSError):
            continue
    
    return results

def check_hsts(hostname):
    """
    Check for the presence of the HSTS (HTTP Strict Transport Security) header.

    Args:
        hostname (str): The hostname of the server.

    Returns:
        str: The value of the HSTS header or an error message.
    """
    try:
        response = requests.get(f"https://{hostname}", timeout=10)
        hsts = response.headers.get('Strict-Transport-Security', 'Not Found')
    except requests.RequestException as e:
        hsts = f"Error: {e}"
    return hsts

def print_formatted_info(cert_info, protocols, cipher_info, deprecated_protocols, hsts_info):
    """
    Print the formatted information.

    Args:
        cert_info (list): Certificate information.
        protocols (list): List of supported protocols.
        cipher_info (list): List of supported cipher suites.
        deprecated_protocols (list): List of deprecated protocols.
        hsts_info (str): HSTS header information.
    """
    print("\nCertificate Information:")
    print(tabulate(cert_info, headers=["Field", "Value"], tablefmt="grid"))
    
    print("\nSupported Protocols:")
    print(tabulate([[protocol] for protocol in protocols], headers=["Protocol"], tablefmt="grid"))
    
    print("\nCipher Suite Information:")
    print(tabulate(cipher_info, headers=["Cipher Suite", "Description"], tablefmt="grid"))

    print("\nDeprecated Protocols:")
    if deprecated_protocols:
        print(tabulate([[protocol] for protocol in deprecated_protocols], headers=["Deprecated Protocol"], tablefmt="grid"))
    else:
        print("No deprecated protocols detected.")

    print("\nHSTS Information:")
    print(f"HSTS Header: {hsts_info}")

def main():
    """
    Main function to execute the SSL/TLS checker.
    """
    hostname = input("Enter the website URL (e.g., example.com): ").strip()
    try:
        cert = get_certificate_info(hostname)
        cert_info = format_certificate_info(cert)
        protocols, cipher_info = check_tls_config(hostname)
        deprecated_protocols = check_deprecated_protocols(hostname)
        hsts_info = check_hsts(hostname)
        print_formatted_info(cert_info, protocols, cipher_info, deprecated_protocols, hsts_info)
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
