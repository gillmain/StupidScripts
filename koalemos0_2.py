#! usr/bin/python

import json as simplejson
import urllib, urllib2
import httplib
import socket
import shutil
import sys
import re
import os
import time
import datetime
from optparse import OptionParser
#from netcat import *

key_count = 0
name = datetime.datetime.now()
current = name.strftime("%Y%m%d_%H%M")

abs_path = os.getcwd()
log_path = "\\log"
results_path = "\\results"
reports_path = "\\reports"
vt_path = "\\virustotal"
te_path = "\\threatexpert"
good_path = "\\good"
bad_path = "\\bad"
unknown_path = "\\unknown"
cymru_path = "\\cymru"

vt_apikey = [""]	#Comma separated keys go here

sleeper = 15 / len(vt_apikey)
				
				
ofilestr = "%s_output.log" % current
good_report = "%s_virustotal_good.results" % current
bad_report = "%s_virustotal_bad.results" % current
not_found_report = "%s_virustotal_not_found.results" % current

def main():

	parser = OptionParser()
	parser.add_option("-f", "--file", action="store",
						dest="filename", default=False, help="insert bulk MD5 signatures file")
	parser.add_option("-v", "--virustotal", action="store_true",
						dest="virustotal", default=False, help="use VirusTotal")
	parser.add_option("-t", "--threatexpert", action="store_true",
					    dest="threatexpert", default=False, help="use ThreatExpert")
	parser.add_option("-c", "--cymru", action="store_true",
						dest="cymru", default=False, help="use Team Cymru")
	parser.add_option("-p", "--herdprotect", action="store_true",
						dest="herdprotect", default=False, help="use Herd Protect")
	parser.add_option("-m", "--metascan", action="store_true",
						dest="metascan", default=False, help="use Metascan")
	parser.add_option("-o", "--output", action="store_true",
						dest="output", default=False, help="provide output file")
	
	(opts, args) = parser.parse_args()

## ----------------------------- Logging ------------------------------ ##	
	check_path(abs_path, log_path)
	check_path(abs_path, reports_path)
	check_path(abs_path, (log_path + vt_path))
	check_path(abs_path, (log_path + te_path))
	check_path(abs_path, (reports_path + good_path))
	check_path(abs_path, (reports_path + bad_path))
	check_path(abs_path, (reports_path + unknown_path))
	check_path(abs_path, (results_path + bad_path))
	check_path(abs_path, (results_path + good_path))
	check_path(abs_path, (results_path + unknown_path))
	check_path(abs_path, cymru_path)
	
## ---------------------------- User Options -------------------------- ##
	if opts.filename == None:
		parser.print_help()
	
	if opts.filename:
		if not os.path.isfile(opts.filename):
			parser.error("%s does not exist" % opts.filename)
		else:
			with open(opts.filename, 'r') as md5hashes_file:
				md5hashes = md5hashes_file.read().splitlines()
	else:
		parser.print_help()
		
	if opts.virustotal:
		virustotal(md5hashes)
	if opts.threatexpert:
		threatexpert(md5hashes)
	if opts.cymru:
		if opts.output == None:
			parser.print_help()
		else:
			cymru(opts.filename, opts.output)
	if opts.herdprotect:
		herdprotect(md5hases)
	if opts.metascan:
		metascan(md5hashes)

		
## ---------------------------- Functions -------------------------- ##		
def virustotal(md5hashes):
## Function to submit MD5 hashes to VirusTotal
	x = sum(1 for line in md5hashes)
	print "Estimated Time to Complete: ", (x * sleeper / 60), "minutes \n"
	
	url = "https://www.virustotal.com/vtapi/v2/file/report"
	current = 0
	key_count = 0
	try:	
		for hash in md5hashes:
			current = current + 1
			key_count = key_count + 1 # Instantiating which API key to use
			print current, "/", x, "(", ((x - current) * sleeper / 60), "minutes remaining )"
			
			# Rotating the API keys
			if key_count == 1:
				key = vt_apikey[0]
			elif key_count == 2:
				key = vt_apikey[1]
			elif key_count == 3:
				key = vt_apikey[2]
			elif key_count == 4:
				key = vt_apikey[3]
				key_count = 0
			
			parameters = {"resource": hash,							
					"apikey": key}

			data = urllib.urlencode(parameters)							# 
			req = urllib2.Request(url,data)								#
			response = urllib2.urlopen(req)								#
			json = response.read()										# This was all taken
																		# directly from the 
			response_dict = simplejson.loads(json)						# VirusTotal API 
			response_code = response_dict.get("response_code", {})		# website.
			positives = response_dict.get("positives", {})				#
			total = response_dict.get("total", {})						#
			md5 = response_dict.get("md5", {})							#
			
			if response_code == 1: # Expected response from VirusTotal
				if (positives != 0): # We want to look at anything that returns a positive value 
					print 'MD5 hash %s warrants further investigation.' % md5 + '( ' + str(positives) + ' / ' + str(total) + ' )'
					bad_hash = [md5]
					for hash in bad_hash:
						with open(abs_path + results_path + bad_path + "\\" + bad_report, 'a') as badder:
							badder.write(str(hash) + '\n') # Write to bads report			
				else:
					print "MD5 hash %s is clean." % md5
					good_hash = [md5]
					for hash in good_hash:
						with open(abs_path + results_path + good_path + "\\" + good_report, 'a') as gooder:
							gooder.write(str(hash) + '\n') # Write to goods report
			else:
				print "Not Found: \t", hash
				unknown_hash = [hash]
				for hash in unknown_hash:
					with open(abs_path + results_path + unknown_path + "\\" + not_found_report, 'a') as check:
						check.write(str(hash) + '\n') # Write to unknowns report
								
			with open(abs_path + log_path + ofilestr, 'a') as ofileobj: # JSON dump 
				simplejson.dump(json, ofileobj)
				ofileobj.write("\n")
				
			time.sleep(sleeper) # Sleep for appropriate so as to not piss off VirusTotal
	except Exception as e:
		print str(e)
		
		
def threatexpert(md5hashes):
## Function to submit MD5 hashes to ThreatExpert
	for md5 in md5hashes:
		search_url = 'http://www.threatexpert.com/report.aspx?md5=' + md5
		print "Checking ThreatExpert for file with MD5: %s" % md5
		try:
			conn = httplib.HTTPConnection('www.threatexpert.com')
			conn.request('GET', '/report.aspx?md5=' + md5)
			response = conn.getresponse().read()
			if response.find('Submission Summary') != -1:
				print "Analysis exists: %s" % search_url
			else:
				print "Analysis does not yet exist!"
		except Exception, e:
			print "Error searching for hash: %s" % e
			pass
		
		with open(ofilestr, 'a') as ofileobj:
			simplejson.dump(response, ofileobj)
			ofileobj.write("\n")

def cymru(md5hashes, output):
## Function to submit MD5 hashes to Team Cymru
	cymru_file = abs_path + '%s_cymru.log' % current
	cymru_results = abs_path + results_path + cymru_path + '%s_cymru.results' % current
	shutil.copyfile(md5hashes, cymru_file)
	
	netcat = "nc.exe hash.cymru.com 43 < " + cymru_file + " > " + cymru_rseults
	os.system(netcat)

## ------------------------ Future development ------------------------ ##
#def herdprotect(md5hashes):
# def metascan(md5hashes):
	# print md5hashes
	# metascan_dict = {'hash': ''}
	# metascan_dict['hash'] = md5hashes
	
		

#def plaguescanner(md5hashes):

## ----------------------------- Logging ------------------------------ ##
def check_path(abs_path, path):
	dir = abs_path + path
	if not os.path.isdir(abs_path + path):
		os.makedirs(dir)
	return dir
			
if __name__ == "__main__":
	main()