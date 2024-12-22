from flask import Flask, request, jsonify
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import socket
import os
import json
from flask_socketio import SocketIO, emit, Namespace


app = Flask(__name__)
app.config['SECRET_KEY'] = '1CFWJBFJ14R!@R1234c!@4c@34c!34C1234!c@149590C2'
socketio = SocketIO(app, cors_allowed_origins="*")


API_KEY = "3503fb6f18d5420cb8fa6217fcf7cc38"
SUBDOMAIN_API_KEY = "at_aGcxXGpmR97FJZlGP9VWrKmWPCkPq"

# Function to load existing URL data from JSON file
def load_url_data(type):
    if os.path.exists(f'{type}.json'):
        with open(f'{type}.json', 'r') as f:
            return json.load(f)
    else:
        return {}

# Function to save URL data to JSON file
def save_url_data(type, data):
    with open(f'{type}.json', 'w') as f:
        json.dump(data, f, indent=4)


# Function to check if the URL is valid
def is_valid_url(url):
    try:
        result = urlparse(url)
        return (all([result.scheme, result.netloc]), result)
    except ValueError:
        return False, None


# Function to get domain information from ipgeolocation
def get_domain_info(ip_address):
    url_data = load_url_data("url_data")
    
    if ip_address in url_data:
        return url_data[ip_address]
    else:
        REQUEST_URL = f"https://api.ipgeolocation.io/ipgeo?apiKey={API_KEY}&ip={ip_address}"
        info = requests.get(REQUEST_URL).json()
        
        url_data[ip_address] = info
        save_url_data("url_data", url_data)
        
        return info


# Function to get IP address of the domain
def get_ip_address(url):
    try:
        ip_address = socket.gethostbyname(url)
        return ip_address
    except Exception as err:
        print("Error: {}".format(err))
        return None


# Function to get subdomains of the domain from whoisxmlapi
def get_subdomains(url):
    subdomains_data = load_url_data("subdomains")

    if url in subdomains_data:
        return subdomains_data[url]

    URL = f"https://subdomains.whoisxmlapi.com/api/v1?apiKey={SUBDOMAIN_API_KEY}&domainName={url}"
    subdomains = requests.get(URL).json()

    subdomain_list = []

    subdomains = subdomains.get("result", {}).get("records", [])

    for subdomain in subdomains:
        subdomain_list.append(subdomain.get("domain"))

    subdomains_data[url] = subdomain_list

    save_url_data("subdomains", subdomains_data)

    return subdomain_list


# Function to get webpage information using BeautifulSoup
def get_webpage_info(url):
    webpage_data = load_url_data("webpage_data")

    if url in webpage_data:
        return webpage_data[url]
    

    webpage_info = {}
    response = requests.get(url)
    if response.status_code == 200:
        soup = BeautifulSoup(response.text, 'html.parser')
        # Extracting style sheets
        webpage_info['stylesheets'] = [link.get('href') for link in soup.find_all('link', rel='stylesheet')]
        # Extracting javascripts
        webpage_info['javascripts'] = [script.get('src') for script in soup.find_all('script')]
        # Extracting images
        webpage_info['images'] = [img.get('src') for img in soup.find_all('img')]
        # Extracting iframe sources
        webpage_info['iframes'] = [iframe.get('src') for iframe in soup.find_all('iframe')]
        # Extracting anchor tag references
        webpage_info['anchors'] = [a.get('href') for a in soup.find_all('a')]

        webpage_data[url] = webpage_info
        
        save_url_data("webpage_data", webpage_data)

        return webpage_info
    
    return None


@app.route('/analyze_website', methods=['GET'])
def analyze_website():
    url = request.args.get('url')

    valid, parsed_url= is_valid_url(url)

    if not valid:
        return jsonify({"error": "URL parameter is missing or malformed"}), 400

    # GET IP ADDRESS
    ip_address = get_ip_address(parsed_url.netloc)
    
    if ip_address is None:
        return jsonify({"error": "Unable to get IP address"}), 500

    
    info = get_domain_info(ip_address)

    analysis_result = {
        "Server IP": ip_address,
        "Location": info.get("country_name_official", "N/A"),
        "ASN": info.get("asn", "N/A"),
        "ISP": info.get("isp", "N/A"),
        "Organization": info.get("organization", "N/A"),
    }

    # Subdomains
    subdomains = get_subdomains(parsed_url.netloc)

    analysis_result["subdomains_list"] = len(subdomains)

    # Webpage Info
    webpage_info = get_webpage_info(url)

    if webpage_info:
        analysis_result.update(
            {
                "webpage_info": webpage_info,
            }
        )

    return jsonify(analysis_result)


class AnalyzeWebsite(Namespace):

    URL = None
    PARSED_URL = None

    def on_connect(self):
        print("Client connected")

    def on_disconnect(self):
        self.URL = None
        self.PARSED_URL = None
        print("Client disconnected")

    def on_message(self, data):
        data = json.loads(data)
        
        if data.get("url"):
            URL = data.get("url")
            valid, parsed_url = is_valid_url(URL)

            if not valid:
                return emit('my_response', {"status": "error", "message": "URL parameter is missing or malformed"})
            else:
                self.URL = URL
                self.PARSED_URL = parsed_url

            return emit('my_response', {"status": "success", "message": "URL set successfully"})
        elif self.URL is None:
            return emit('my_response', {"status": "error", "message": "URL parameter is missing"})

        if data.get("operation"):
            if data.get("operation") == "get_info":
                # GET IP ADDRESS
                ip_address = get_ip_address(self.PARSED_URL.netloc)
                info = get_domain_info(ip_address)
                return emit('my_response', {"data": info })
            elif data.get("operation") == "get_subdomains":
                subdomains = get_subdomains(self.PARSED_URL.netloc)
                return emit('my_response', {"data": subdomains})
            elif data.get("operation") == "get_asset_domains":
                webpage_info = get_webpage_info(self.URL)
                return emit('my_response', {"data": webpage_info})


socketio.on_namespace(AnalyzeWebsite('/ws'))


if __name__ == '__main__':
    socketio.run(app)

