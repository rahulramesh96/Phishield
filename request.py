import requests
import virustotal_python
from pprint import pprint
from base64 import urlsafe_b64encode
import sys
import datetime

def url_analysis():

	print("Done! Check the logs in the current directory.")	
	filename1 = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
	sys.stdout = open(filename1 + '.csv', 'w')



	f = open('read.txt')
	domain = f.readlines()
	count = 0
	print(domain[count])


	while(domain[count]!=0):
		try:

			id = urlsafe_b64encode(domain[count].encode()).decode().strip("=")
			print(id)
			

			url = "https://www.virustotal.com/api/v3/urls/"+id
			print(url)

			headers = {
			    "Accept": "application/json",
			    "x-apikey": ""
			    }

			response = requests.get(url, headers=headers)
			print(response.text)
			

			
			phishing_occurrences = response.text.count('"result": "phishing"')
			malicious_occurrences = response.text.count('"result": "malicious"')
			suspicious_occurrences = response.text.count('"result": "suspicious"')

			print('website:\t\t\t\t' ,domain[count])
			print('No. of Vendors flagged as Phishing :\t\t', phishing_occurrences)
			print('No. of Vendors flagged as Malicious :\t\t', malicious_occurrences)
			print('No. of Vendors flagged as Suspicious :\t\t', suspicious_occurrences)
			print()
			print()
	
			with open(filename1+'.csv', "r+") as external_file:
				print(response.text, file=external_file)
				count+=1

			
		except virustotal_python.VirustotalError as err:
			print(f"Failed to send URL: {url} for analysis and get the report: {err}")



choice = sys.argv[1]

if(choice == '-u'):
	url_analysis()
