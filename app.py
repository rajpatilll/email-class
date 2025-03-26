
from flask import Flask, render_template, request
import dns.resolver
import whois
import ssl
import socket
from datetime import datetime


app = Flask(__name__)

def analyze_spf(domain):
    try:
        txt_records = dns.resolver.resolve(domain, 'TXT')
        for record in txt_records:
            if "v=spf1" in str(record):
                return f"SPF Validated: {record}"
        return "No SPF record found."
    except dns.resolver.NXDOMAIN:
        return "No DNS records found for the domain."
    except dns.resolver.NoAnswer:
        return "No SPF record found in the DNS records."
    except dns.resolver.Timeout:
        return "DNS query timed out for SPF check."
    except Exception as e:
        return f"SPF Check Error: {e}"

def analyze_dmarc(domain):
    try:
        dmarc_domain = "_dmarc." + domain
        txt_records = dns.resolver.resolve(dmarc_domain, 'TXT')
        for record in txt_records:
            if "v=DMARC1" in str(record):
                return f"DMARC Record Found: {record}"
        return "No DMARC record found."
    except dns.resolver.NXDOMAIN:
        return "No DNS records found for the domain."
    except dns.resolver.NoAnswer:
        return "No DMARC record found in the DNS records."
    except dns.resolver.Timeout:
        return "DNS query timed out for DMARC check."
    except Exception as e:
        return f"DMARC Check Error: {e}"

def analyze_url(url):
    try:
        domain = url.split('/')[2]  # Extract domain from URL
        a_records = dns.resolver.resolve(domain, 'A')
        return f"Resolved IPs: {[str(r) for r in a_records]}"
    except dns.resolver.NXDOMAIN:
        return "The domain does not exist. It may be malicious or inactive."
    except dns.resolver.NoAnswer:
        return "No DNS records found for the domain."
    except dns.resolver.Timeout:
        return "DNS query timed out for the URL."
    except Exception as e:
        return f"URL Analysis Error: {e}"



def check_ssl(domain):
    try:
        # Create a default SSL context
        context = ssl.create_default_context()
        
        # Connect to the server using SSL
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

        # Extract certificate details
        issuer = dict(x[0] for x in cert['issuer'])
        issued_by = issuer.get('organizationName', 'Unknown')
        valid_from = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
        valid_to = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')

        # Check if the certificate is still valid
        current_date = datetime.utcnow()
        if current_date > valid_to:
            return f"SSL Certificate expired on {valid_to}."
        elif current_date < valid_from:
            return f"SSL Certificate is not yet valid (valid from {valid_from})."

        return f"SSL Certificate is valid. Issued by: {issued_by}. Valid until: {valid_to}."
    except ssl.SSLCertVerificationError:
        return "SSL Certificate verification failed."
    except socket.timeout:
        return "Connection to the domain timed out."
    except Exception as e:
        return f"SSL Check Error: {e}"

def classify_phishing(spf_result, dmarc_result, url_result):
    """
    Classify the input as phishing or non-phishing based on SPF, DMARC, and URL results.
    """
    score = 0
    reasons = []

    # Check SPF
    if "No SPF record found" in spf_result or "SPF Check Error" in spf_result:
        score += 1
        reasons.append("SPF validation failed.")
    elif "SPF Validated" in spf_result:
        score -= 1

    # Check DMARC
    if "No DMARC record found" in dmarc_result or "DMARC Check Error" in dmarc_result:
        score += 1
        reasons.append("DMARC validation failed.")
    elif "DMARC Record Found" in dmarc_result:
        score -= 1

    # Check URL
    if "does not exist" in url_result or "URL Analysis Error" in url_result:
        score += 2
        reasons.append("The URL is invalid or does not exist.")
    elif "SSL Certificate expired" in url_result or "SSL Check Error" in url_result:
        score += 1
        reasons.append("The SSL certificate is invalid or expired.")
    elif "SSL Certificate is valid" in url_result:
        score -= 1

    # Final classification
    if score > 0:
        return "Phishing", reasons
    else:
        return "Non-Phishing", reasons


@app.route('/')
def home():
    return render_template('home.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    email = request.form.get('email')
    url = request.form.get('url')
    domain = email.split('@')[1] if email else "No Domain"

    # Perform SPF and DMARC Analysis
    spf_result = analyze_spf(domain) if domain else "No domain found in email."
    dmarc_result = analyze_dmarc(domain) if domain else "No domain found in email."

    # Perform URL Analysis
    url_result = analyze_url(url) if url else "No URL provided."

    # Classify as Phishing or Non-Phishing
    classification, reasons = classify_phishing(spf_result, dmarc_result, url_result)

    return render_template(
        'result.html',
        spf_result=spf_result,
        dmarc_result=dmarc_result,
        url_result=url_result,
        classification=classification,
        reasons=reasons
    )

if __name__ == '__main__':
    app.run(debug=True)
