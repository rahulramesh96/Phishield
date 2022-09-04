import requests
import virustotal_python
from pprint import pprint
from base64 import urlsafe_b64encode



api_key = "588852b936b5f44f9bada3b2d4b8d5a8933c21950fa592f36a540a2ef9eff806"


f = open('read.txt')
domain = f.readlines()
count = 0
print(domain[count])


while(domain[count] != 0):

	with virustotal_python.Virustotal(api_key) as vtotal:
		try:

			id = urlsafe_b64encode(domain[count].encode()).decode().strip("=")
			print(id)
			

			url = "https://www.virustotal.com/api/v3/urls/"+id

			headers = {
			    "Accept": "application/json",
			    "x-apikey": "588852b936b5f44f9bada3b2d4b8d5a8933c21950fa592f36a540a2ef9eff806"
			    }

			response = requests.get(url, headers=headers)

			phishing_occurrences = response.text.count('"result": "phishing"')
			malicious_occurrences = response.text.count('"result": "malicious"')
			print(response.text)
			print("website:\t\t\t\t" ,domain[count])
			print('No. of Vendors flagged as Phishing :\t\t', phishing_occurrences)
			print('No. of Vendors flagged as Malicious :\t\t', malicious_occurrences)
			count+=1


		except virustotal_python.VirustotalError as err:
	            print(f"Failed to send URL: {url} for analysis and get the report: {err}")

