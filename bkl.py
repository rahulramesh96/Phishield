import virustotal_python
from pprint import pprint
from base64 import urlsafe_b64encode
import sys
import csv
import time
import datetime

filename1 = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
sys.stdout = open(filename1 + '.csv', 'w')


f = open("read.txt")
lines = f.readlines()
for url in lines:
    print(url)


    api_key = "3c62f73863cb05b103768d181418575f091e74d70a4b04e12bda4c4ad9761ca3"

    with virustotal_python.Virustotal(api_key) as vtotal:
        try:
            resp = vtotal.request("urls", data={"url": url}, method="POST")
            # Safe encode URL in base64 format
            # https://developers.virustotal.com/reference/url
            url_id = urlsafe_b64encode(url.encode()).decode().strip("=")
            report = vtotal.request(f"urls/{url_id}")
            pprint(report.object_type)
            pprint(report.data)
            with open(filename1+'.csv', "r+") as external_file:
                # add_text = "This text will be added to the file"
                print(report.data, file=external_file)

                data = external_file.readline()


                # get number of occurrences of the substring in the string
                phishing_occurrences = data.count("'result': 'phishing'")
                malicious_occurrences = data.count("'result': 'malicious'")

                print('No. of Vendors flagged as Phishing :', phishing_occurrences)
                print('No. of Vendors flagged as Malicious :', malicious_occurrences)
                print()
                external_file.close()

        except virustotal_python.VirustotalError as err:
            print(f"Failed to send URL: {url} for analysis and get the report: {err}")
f.close()