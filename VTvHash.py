#Maltego Transfrom - VirusTotal vHash pivot @arieljt

from MaltegoTransform import *
import requests
import json

apiurl = "https://www.virustotal.com/api/v3/"
apikey = ""

mt = MaltegoTransform()
mt.parseArguments(sys.argv)
file_hash = mt.getVar('properties.hash').strip()


try:
    headers = {'x-apikey': apikey}
    response = requests.get(apiurl + 'files/' + file_hash, headers=headers) 
    response_json = response.json()

    if 'vhash' in response_json['data']['attributes']:
		vhash = response_json['data']['attributes']['vhash'].encode("ascii")
		response = requests.get(apiurl + 'intelligence/search?query=vhash:"%s"' %vhash, headers=headers)
		response_json = response.json()
		for item in response_json['data']:
			me = mt.addEntity("maltego.Hash", '%s' % item['attributes']['md5'].encode("ascii"))
			me.setLinkLabel("vHash %s" % vhash)

except:
    mt.addUIMessage("Exception Occurred")

    
mt.returnOutput()


