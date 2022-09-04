import requests

url = "https://www.virustotal.com/api/v3/urls/aHR0cDovL2FkdmVydGEuaHIK"

headers = {
    "Accept": "application/json",
    "x-apikey": "8dbdf96716379ba0a7ebca3082cca1bc0b9c8f131a239f0511d975ce78f4961f"
}

response = requests.get(url, headers=headers)

print(response.text)