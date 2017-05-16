# ELECTRICFENCE Version 1.0
##
## Created by:
## 	Mr. Ryan McCombs
##	National Cyber Protection Team 81
##	Discover & Counter Infiltration Squad
##	Email: rwmccom@nsa.gov
##
##


# Imports
import re
import sys
import subprocess
from subprocess import CalledProcessError, check_output
from optparse import OptionParser
import socket

# Constants
rule = ['']

# Functions
def whitelist(whitelist_ips):
	# Input the standard stuff into the whitelist
	good_ips = ['0.0.0.0','127.0.0.1']
	
	# Turn on the Windows Firewall if it is disables
	subprocess.check_output('netsh advfirewall set domainprofile state on', shell=True)
	subprocess.check_output('netsh advfirewall set publicprofile state on', shell=True)
	subprocess.check_output('netsh advfirewall set privateprofile state on', shell=True)
	
	# Loop to keep the application going until we end it.
	while True:
		try:
			# Get the netstat output and parse
			netstat = subprocess.check_output("netstat -ano", shell=True)
			netstat = ' '.join(netstat.split())
			netstat = netstat.split(' ')

			# Get the Local IP Address to add to the whitelist
			hostname = socket.gethostname()
			good_ips.append(socket.gethostbyname(hostname))

			# Parse the user argument IP Addresses
			for i in whitelist_ips.split(','):
				good_ips.append(i)
			
			# Instantiate the list for netstat IP Addresses
			ips = []
			
			# Parse netstat for IP Addresses and append to ips list.
			for i in netstat:
				regex = re.findall('(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})',i)
				regex = ''.join(regex)
				if regex is not None and regex not in ips:
					ips.append(regex)

			# Create firewall rule for IP not in the whitelist.
			for i in ips:
				if not i in good_ips:
					if not i in rule:	# This was needed so as to not created a litany of firewall rules for the same IP Address.
						rule.append(i)
						firewall_add = 'netsh advfirewall firewall add rule name="%s" dir=out action=block remoteip=%s' % (i,i)
						subprocess.check_output(firewall_add, shell=True)
						print "Blocking IP Address: %s\n" % i
		
		# Script end and cleanup.
		except KeyboardInterrupt:
			for i in rule:
				firewall_delete = ('netsh advfirewall firewall delete rule name="%s"' % i)
				try:
					subprocess.check_output(firewall_delete, shell=True)
					print 'Deleting firewall rule for %s' % i
				except CalledProcessError as e:
					pass
			sys.exit()
	
def main():
	# User arguments
	usage = "Usage: %prog [options] IP1,IP2,etc."
	parser = OptionParser(usage=usage)
	parser.add_option("-w", action="store", dest="whitelist", 
						default=False, help="supply comma seperated list of whitelisted IPs")
						
	(opts, args) = parser.parse_args()

	if opts.whitelist is False:
		parser.print_help()
	if opts.whitelist is None:
		parser.print_help()
	if opts.whitelist:
		print "Don't taste me bro!"
		whitelist(opts.whitelist)
	


# Main
if __name__ == "__main__":
	main()