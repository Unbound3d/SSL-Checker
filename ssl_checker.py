import ssl
import socket
from datetime import datetime
import argparse
import OpenSSL
import OpenSSL.crypto

SOCKET_TIMEOUT = 5  # 5-second timeout
LOCAL_CA_CERT_PATH = 'ca.crt'  # Path to local CA certificate

def load_local_ca_cert(ca_path):
    """Load the local CA certificate."""
    with open(ca_path, 'r') as f:
        ca_cert = f.read()
    return OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, ca_cert)

def clean_domain(domain):
    # Remove "https://", "http://", and any paths
    domain = domain.strip().replace("https://", "").replace("http://", "").split("/")[0]
    # Remove port numbers if present (e.g., example.com:443)
    domain = domain.split(":")[0]
    return domain

def get_service(domain):
    # Extract the subdomain (e.g., "partners" from "partners.domain.com")
    parts = domain.split(".")
    if len(parts) > 2:  # If there's a subdomain
        return parts[0]  # Return the subdomain as the service
    return "main"  # If no subdomain, return "main"

def get_ssl_expiry_date(domain, local_ca_cert):
    try:
        # Create a default SSL context
        context = ssl.create_default_context()
        context.check_hostname = False  # Disable hostname verification
        context.verify_mode = ssl.CERT_NONE  # Disable certificate verification
        socket.setdefaulttimeout(SOCKET_TIMEOUT)

        # Connect to the domain and fetch the certificate
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert(binary_form=True)
                x509_cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert)

                # Extract expiry and issue dates
                expiry_date = datetime.strptime(x509_cert.get_notAfter().decode('utf-8'), '%Y%m%d%H%M%SZ')
                issue_date = datetime.strptime(x509_cert.get_notBefore().decode('utf-8'), '%Y%m%d%H%M%SZ')

                # Extract the issuer organization name correctly
                issuer_components = x509_cert.get_issuer().get_components()
                issuer_dict = {key.decode('utf-8'): value.decode('utf-8') for key, value in issuer_components}
                issuer = issuer_dict.get('O', 'BRITAMGROUP-BAEQDCERTSVR1-CA')

                # Check if the certificate is signed by the local CA
                local_ca_issuer_components = local_ca_cert.get_subject().get_components()
                local_ca_dict = {key.decode('utf-8'): value.decode('utf-8') for key, value in local_ca_issuer_components}
                is_local_ca = (local_ca_dict.get('O') == issuer)

                return issue_date, expiry_date, issuer, is_local_ca

    except Exception as e:
        print(f"Error fetching SSL certificate for {domain}: {e}")
        return None, None, "Unknown", False

def create_bordered_table(results):
    # Define the table headers
    headers = ["URL", "Is Expired", "Issue Date", "Expiry Date", "Issuer", "Service", "Days Remaining", "Self Signed"]
    # Define the column widths
    col_widths = [max(len(str(row["url"])) for row in results) + 2,
                  max(len(str(row["is_expired"])) for row in results) + 2,
                  max(len(str(row["issue_date"])) for row in results) + 2,
                  max(len(str(row["expiry_date"])) for row in results) + 2,
                  max(len(str(row["issuer"])) for row in results) + 2,
                  max(len(str(row["service"])) for row in results) + 2,
                  max(len(str(row["days_remaining"])) for row in results) + 2,
                  max(len(str(row["is_local_ca"])) for row in results) + 2]
    # Ensure headers fit
    for i, header in enumerate(headers):
        if len(header) > col_widths[i]:
            col_widths[i] = len(header) + 2

    # Create the table border
    border = "+" + "+".join(["-" * (width + 2) for width in col_widths]) + "+"

    # Build the table
    table = []
    table.append(border)
    # Add headers
    header_row = "|" + "|".join([f" {headers[i].ljust(col_widths[i])} " for i in range(len(headers))]) + "|"
    table.append(header_row)
    table.append(border)
    # Add rows
    for row in results:
        row_data = [
            row["url"],
            row["is_expired"],
            row["issue_date"],
            row["expiry_date"],
            row["issuer"],
            row["service"],
            row["days_remaining"],
            row["is_local_ca"]
        ]
        row_str = "|" + "|".join([f" {str(row_data[i]).ljust(col_widths[i])} " for i in range(len(row_data))]) + "|"
        table.append(row_str)
    table.append(border)
    return "\n".join(table)

def check_domains(domains, output_file, local_ca_cert):
    results = []
    for domain in domains:
        if domain.strip():  # Skip empty lines
            # Clean the domain (remove https://, http://, paths, and ports)
            domain = clean_domain(domain)
            issue_date, expiry_date, issuer, is_local_ca = get_ssl_expiry_date(domain, local_ca_cert)
            service = get_service(domain)
            if expiry_date:
                is_expired = "Yes" if expiry_date < datetime.now() else "No"
                days_remaining = (expiry_date - datetime.now()).days if expiry_date > datetime.now() else 0
                results.append({
                    "url": domain,
                    "is_expired": is_expired,
                    "issue_date": issue_date.strftime('%Y-%m-%d'),
                    "expiry_date": expiry_date.strftime('%Y-%m-%d'),
                    "issuer": issuer,
                    "service": service,
                    "days_remaining": days_remaining,
                    "is_local_ca": "Yes" if is_local_ca else "No"
                })
            else:
                # Log domains with errors or timeouts
                results.append({
                    "url": domain,
                    "is_expired": "Unresponsive" if issue_date is None else "Error",
                    "issue_date": "N/A",
                    "expiry_date": "N/A",
                    "issuer": "Unknown",
                    "service": service,
                    "days_remaining": "N/A",
                    "is_local_ca": "N/A"
                })

    # Create the bordered table
    table = create_bordered_table(results)

    # Write results to the output file
    with open(output_file, 'w') as file:
        file.write(table)

    print(f"Results written to {output_file}")

def main():
    # Log script description and version
    print("SSL_checker V1.0.")
    print("A simple script written by Erick Mutisya (@Unbound3d on Github)")
    print("https://github.com/Unbound3d")
    print("\n")

    # Set up argument parser
    parser = argparse.ArgumentParser(
        description="Check SSL certificate expiry for domains. A simple script written by Erick Mutisya (@Unbound3d on Github).",
        epilog="Example usage:\n"
               "  python ssl_checker.py -u https://example.com\n"
               "  python ssl_checker.py -f domains.txt -o results.txt",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("-f", "--file", help="Path to a file containing domains (one per line).")
    parser.add_argument("-u", "--url", help="A single domain to check.")
    parser.add_argument("-o", "--output", default="results.txt", help="Output file to save results (default: results.txt).")
    args = parser.parse_args()

    # Validate input
    if not args.file and not args.url:
        parser.print_help()
        print("\nError: Please provide either a file (-f) or a URL (-u).")
        return

    # Read domains from file or URL
    domains = []
    if args.file:
        try:
            with open(args.file, 'r') as file:
                domains = file.read().splitlines()
        except FileNotFoundError:
            print(f"Error: File '{args.file}' not found.")
            return
    if args.url:
        domains.append(args.url)

    # Load the local CA certificate
    local_ca_cert = load_local_ca_cert(LOCAL_CA_CERT_PATH)
    print(f"Local CA Subject: {local_ca_cert.get_subject().CN}")

    # Check domains and save results
    check_domains(domains, args.output, local_ca_cert)

if __name__ == "__main__":
    main()
