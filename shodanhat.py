#!/usr/bin/env python
# -*- coding: utf-8 -*-

import optparse, shodan, sys
from constantes import *

def banner():
	print "███████╗██╗  ██╗ ██████╗ ██████╗  █████╗ ███╗   ██╗██╗  ██╗ █████╗ ████████╗"
	print "██╔════╝██║  ██║██╔═══██╗██╔══██╗██╔══██╗████╗  ██║██║  ██║██╔══██╗╚══██╔══╝"
	print "███████╗███████║██║   ██║██║  ██║███████║██╔██╗ ██║███████║███████║   ██║   "
	print "╚════██║██╔══██║██║   ██║██║  ██║██╔══██║██║╚██╗██║██╔══██║██╔══██║   ██║   "
	print "███████║██║  ██║╚██████╔╝██████╔╝██║  ██║██║ ╚████║██║  ██║██║  ██║   ██║   "
	print "╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   "
	print ""
	print "Author: Everton a.k.a XGU4RD14N && Mateus a.k.a Dctor"
	print "Members HatBashBR: Junior a.k.a ASTAROTH, Johnny a.k.a UrdSys, No One, Geovane"
	print "fb.com/hatbashbr"
	print "github.com/hatbashbr"
	print ""
banner()

def printInfo(host):
	print "IP: %s"%host["ip_str"]
	print "Organization: %s"%host.get("org", "n/a")
	print "Operating System: %s"%host.get("os", "n/a")
	print "Latitude: %s"%host["latitude"]
	print "Longitude: %s"%host["longitude"]
	print "City: %s"%host["city"]
	print "Ports: "
	for item in host["data"]:
		print "  [+] %s"%item["port"]

parser = optparse.OptionParser()
parser.add_option("-i", "--ip", dest="ip", help="Info about one host", default="")
parser.add_option("-l", "--list", dest="list", help="Info about a list of hosts", default="")
parser.add_option("-s", "--sq", dest="sq", help="searchquery string", default="")
options, args = parser.parse_args()

if SHODAN_API_KEY == "":
	print "You need to set the API Key in the file 'constantes.py'"
	sys.exit()
	
if options.ip != "" and options.list != "":
	print "You can't use '-i' with '-l'!"
	sys.exit()

api = shodan.Shodan(SHODAN_API_KEY)

try:
	if options.ip != "":	
		host = api.host(options.ip)
		printInfo(host)
	elif options.list != "":
		f = open(options.list)
		for ip in f.readlines():
			host = api.host(ip)
			printInfo(host)
			print
			
	if options.sq != "":
		result = api.search(options.sq)
		print "##### IP's that match the query '%s' #####"%options.sq
		for service in result['matches']:
			print service['ip_str']
except shodan.APIError as e:
	print "Error: "+str(e)
except IOError:
	print "We can't open you list of hosts!"
except Exception as e:
	print "Error: "+str(e)