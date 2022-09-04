import requests
import virustotal_python
from pprint import pprint
from base64 import urlsafe_b64encode



api_key = "3c62f73863cb05b103768d181418575f091e74d70a4b04e12bda4c4ad9761ca3"
domain = "2beecomers.com"


with virustotal_python.Virustotal(api_key) as vtotal:
	try:

		id = urlsafe_b64encode(domain.encode()).decode().strip("=")
		print(id)
		

		url = "https://www.virustotal.com/api/v3/urls/"+id

		headers = {
		    "Accept": "application/json",
		    "x-apikey": "3c62f73863cb05b103768d181418575f091e74d70a4b04e12bda4c4ad9761ca3"
		    }

		response = requests.get(url, headers=headers)

		phishing_occurrences = response.text.count('"result": "phishing"')
		malicious_occurrences = response.text.count('"result": "malicious"')
		print(response.text)
		print("website:\t\t\t\t" ,domain)
		print('No. of Vendors flagged as Phishing :\t\t', phishing_occurrences)
		print('No. of Vendors flagged as Malicious :\t\t', malicious_occurrences)


	except virustotal_python.VirustotalError as err:
            print(f"Failed to send URL: {url} for analysis and get the report: {err}")