#! usr/bin/python
#
#	Postgresql Connect v0.1
#

import psycopg2
import os
import sys
import time
from optparse import OptionParser


now = str(time.strftime("%Y%m%d_%H%M"))
ofile = now + '_stacker_dbquery.log'

unknown_hashdump = now + '_stacker_unknown_dump.log'
unknown_report = now + '_stacker_unknown_report.csv'
bad_hashdump = now + '_stacker_bad_dump.log'
bad_report = now + '_stacker_bad_report.csv'
good_hashdump = now + '_stacker_good_dump.log'
good_report = now + '_stacker_good_report.csv'

u = " is null and user_status is null"
b = " is null and user_status='BAD' or file_status='GOOD' and user_status='BAD' or file_status='BAD' and user_status is null or file_status='BAD' and user_status='BAD'"
g = "='GOOD' and user_status is null or file_status='BAD' and user_status='GOOD' or file_status is null and user_status='GOOD'"

def main():
	parser = OptionParser()
	parser.add_option("-c", "--connect", action="store",
						dest="connect", default=False, help="insert IP address for Stacker server")
	# parser.add_option("-d", "--date", action="store",
						# dest="stack_date", default=False, help="supply the date of the stack")
	parser.add_option("-u", action="store_true",
						dest="unknown", default=False, help="search Stacker DB for all unknown MD5s")
	parser.add_option("-b", action="store_true",
						dest="bad", default=False, help="search Stacker DB for all bad MD5s")
	parser.add_option("-g", action="store_true",
						dest="good", default=False, help="search Stacker DB for all good MD5s")

	(opts, args) = parser.parse_args()

	if not opts.connect and not opts.stack_date:
		parser.print_help()
		parser.error("You must supply appropriate arguments!")
	
	if opts.connect == None:
		parser.print_help()
		parser.error("you must supply an IP Address!")
	elif opts.unknown:
		db_connect(opts.connect, u, unknown_hashdump, unknown_report)
	elif opts.bad:
		db_connect(opts.connect, b, bad_hashdump, bad_report)
	elif opts.good:
		db_connect(opts.connect, g, good_hashdump, good_report)
	
	
def db_connect(ip, status, hashdump, report):
	con = None
	i = 0
	
	directory = os.path.join(os.environ['USERPROFILE'], 'mStacker')
	if not os.path.exists(directory):
		os.makedirs(directory)
	#ofile = directory + '\file_hashes_' + time.strftime("%Y%m%d") + '_' + time.strftime("%H%M%S") + '.log'
	
	try:
		con = psycopg2.connect(host=ip, user='postgres', dbname='stacker')
		cur = con.cursor()
		cur.execute('select * from stackitems where file_status%s;' % status)
		rows = cur.fetchall()

		for row in rows:
			i = i + 1
		
			with open(directory + '\\'  + ofile, 'a') as ofileobj:
				ofileobj.write(str(row) + "\n")
			with open(directory + '\\' + hashdump, 'a') as dmpfileobj:
				dmpfileobj.write(row[3] + '\n')
			with open(directory + '\\'  + report, 'a') as rptfileobj:
				rptfileobj.write(row[7] + '\n')
				
		print str(i) + ' hashes were extracted from stacker.'
		# print cur.execute("select count(*) from stackitems where file_status='GOOD' and user_status is null and CAST(created_at as TEXT) like '2015-07-16%' or file_status='BAD' and user_status='GOOD' and CAST(created_at as TEXT) like '2015-07-16%' or file_status is null and user_status='GOOD' and CAST(created_at as TEXT) like '2015-07-16%';")
		
	except psycopg2.DatabaseError, e:
		print 'Error %s' % e    
		sys.exit(1)

	finally:
		if con:
			con.close()
			
			
if __name__ == "__main__":
	main()