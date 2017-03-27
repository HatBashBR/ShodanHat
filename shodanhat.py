#!/usr/bin/env python
# -*- coding: utf-8 -*-

import optparse, shodan, sys, nmap, urllib2, json
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

hosts = {}

def searchExploits(ip, port):
	if hosts[ip][port][0] == "" or hosts[ip][port][1] == "":
		print "    [-] No exploits could be found"
	else:
		query = "%s %s"%(hosts[ip][port][0], hosts[ip][port][1])
		query = query.replace(" ", "+")
		url = urllib2.urlopen("https://exploits.shodan.io/api/search?query=%s&key=%s"%(query, SHODAN_API_KEY))
		xpls = json.load(url)
		if xpls["total"] > 0:
			print "    Possible Exploits:"
			for i in xpls["matches"]:
				if i.has_key("cve"):
					for cve in i["cve"]:
						print "    [+] CVE: %s"%cve
				elif i.has_key("_id"):
					print "    [+] ID: %s"%i["_id"]
		else:
			print "    [-] No exploits could be found"

def printInfo(host):
	print "IP: %s"%host["ip_str"]
	print "Organization: %s"%host.get("org", "n/a")
	print "Operating System: %s"%host.get("os", "n/a")
	print "Latitude: %s"%host["latitude"]
	print "Longitude: %s"%host["longitude"]
	print "City: %s"%host["city"]
	if options.nmap:
		hosts[str(host["ip_str"])] = {}
		ports = ""
		for item in host["data"]:
			if item == host["data"][-1]:
				ports += str(item["port"])
			else:
				ports += str(item["port"])+","
		
		args = options.scantype
		nm.scan(str(host["ip_str"]), ports, arguments=args)
		if str(host["ip_str"]) in nm.all_hosts():
			print "Ports: "
			for port in nm[str(host["ip_str"])]["tcp"]:
				hosts[host["ip_str"]][port] = [nm[host["ip_str"]]["tcp"][port]["product"],nm[host["ip_str"]]["tcp"][port]["version"]]
				print "  [+] %s\t%s %s %s"%(port, nm[host["ip_str"]]["tcp"][port]["product"], nm[host["ip_str"]]["tcp"][port]["version"], nm[host["ip_str"]]["tcp"][port]["extrainfo"])
				searchExploits(host["ip_str"], port)
		else:
			print "Ports: "
			for item in host["data"]:
				print "  [+] %s"%item["port"]
	else:
		print "Ports: "
		for item in host["data"]:
			print "  [+] %s"%item["port"]
	
	

parser = optparse.OptionParser()
parser.add_option("-i", "--ip", dest="ip", help="info about one host", default="")
parser.add_option("-l", "--list", dest="list", help="info about a list of hosts", default="")
parser.add_option("-s", "--sq", dest="sq", help="searchquery string", default="")
parser.add_option("--nmap", dest="nmap", action="store_true", help="perform a nmap scan in the hosts")
parser.add_option("--setkey", dest="setkey", help="set your api key automatically", default="")
group = optparse.OptionGroup(parser, "NMap Options")
group.add_option("--sS", dest="scantype", action="store_const", help="TCP Syn Scan", const="-sS")
group.add_option("--sT", dest="scantype", action="store_const", help="TCP Connect Scan", const="-sT")
group.add_option("--sU", dest="scantype", action="store_const", help="UDP Scan", const="-sU")
parser.add_option_group(group)
parser.set_defaults(scantype="-sT")
options, args = parser.parse_args()

if options.setkey != "":
	f = open("constantes.py", 'w')
	f.write('SHODAN_API_KEY = "%s"'%options.setkey)
	SHODAN_API_KEY = options.setkey

if SHODAN_API_KEY == "":
	print "You need to set the API Key in the file 'constantes.py' or with the '--setkey' option"
	sys.exit()
	
if options.ip != "" and options.list != "":
	print "You can't use '-i' with '-l'!"
	sys.exit()

api = shodan.Shodan(SHODAN_API_KEY)
nm = nmap.PortScanner()

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
except Exception as e:
	print "Error: "+str(e)