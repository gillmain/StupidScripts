import os
import sys
import uuid
import csv
import datetime
import optparse

def main(source):

	#source = 'Unclassified_Indicators_CHU_20150625'
	template = 'schema.xml'
	
	reader = csv.DictReader(open(source))
	result = {}
	for row in reader:
		for column, value in row.iteritems():
			result.setdefault(column, []).append(value)
	
	# Getting all MD5s in the root 'OR' statement
	l = []
	for i in result['MD5 Hash Value']:
		if i is not '':
			# This was a bitch attempting to get the right formatting for the output.
			l.append('      \
<IndicatorItem id="%s" condition="is">\n        \
<Context document="FileItem" search="FileItem/Md5sum" type="mir" />\n        \
<Content type="md5">%s</Content>\n      \
</IndicatorItem>\n' % (get_guid(),i.lower()))
	
	s = ''.join(l)
	
	# Get everything else.
	m = []
	for i,x in enumerate(result['Malicious File (Attachment)']):
		if x is not '' and '&' not in x:
			# print str(i) + ':' + x + ':' + result['File Size'][i]
			# Check if file has a file size
				if result['File Size'][i] is not '':
					# print str(i) + ':' + x + ':' + result['File Size'][i]
					m.append('      \
<Indicator operator="AND" id="%s">\n        \
<IndicatorItem id="%s" condition="contains">\n          \
<Context document="FileItem" search="FileItem/source" type="mir" />\n          \
<Content type="string">%s</Content>\n        \
</IndicatorItem>\n        \
<IndicatorItem id="%s" condition="is">\n          \
<Context document="FileItem" search="FileItem/SizeInBytes" type="mir" />\n          \
<Content type="int">%s</Content>\n        \
</IndicatorItem>\n      \
</Indicator>\n' % (get_guid(),get_guid(),x,get_guid(),result['File Size'][i]))
			

			
			# Check if file has a location
				if result['File Location (Path)'][i] is not '':
					m.append('      \
<Indicator operator="AND" id="%s">\n        \
<IndicatorItem id="%s" condition="contains">\n          \
<Context document="FileItem" search="FileItem/source" type="mir" />\n          \
<Content type="string">%s</Content>\n        \
</IndicatorItem>\n        \
<IndicatorItem id="%s" condition="is">\n          \
<Context document="FileItem" search="FileItem/FullPath" type="mir" />\n          \
<Content type="string">%s</Content>\n        \
</IndicatorItem>\n      \
</Indicator>\n' % (get_guid(),get_guid(),x,get_guid(),result['File Location (Path)'][i]))
	
	r = ''.join(m)
	p = s + r
	
	schema = open(template, "r")
	data = schema.read()
	schema.close()
	
	
	new_file = data.replace('  <short_description></short_description>', '  <short_description>' 
									+ source + '</short_description>')
	new_file = new_file.replace('    </Indicator>', p + '    </Indicator>')
	new_file = new_file.replace('0b4ea7cb-0feb-42cc-84e2-f5c876e65da4', get_guid())
	
	
	outfile = open('%s.ioc' % source, 'w')
	outfile.write(new_file)
	outfile.close()

def get_guid():
	return str(uuid.uuid4())

def writer_options():
    opts = []
    opts.append(optparse.make_option('-s','--source', dest='src_file', help='source file (CSV) containing IOC data', default=None))  # argument
    #opts.append(optparse.make_option('-n','--name', dest='name', help='ioc name', default=None))  # argument
    #opts.append(optparse.make_option('--or', dest='or_format', action = 'store_true', help='Write out all terms under a OR statemet.  By default, terms are put under a OR-AND structure.', default=False))  # argument
    #opts.append(optparse.make_option('-o', '--output_dir', dest='output_dir', help='location to write IOC to. default is current working directory', default=None))
    return opts	

if __name__ == "__main__":
    usage_str = "usage: %prog [options]"
    print '\n\n Still in development, so please contact the devs with questions/suggestions.\n'
    print '\n   --|81CPT Python Developers|--\n\tRyan McCombs\n\tDaniel Twardowski\n'
    parser = optparse.OptionParser(usage=usage_str, option_list=writer_options())
    options, args = parser.parse_args()
    
    if not options.src_file:
        print 'must specify source file'
        parser.print_help()
        sys.exit(-1)
        
    # if not options.name:
        # print 'must specify an ioc name'
        # parser.print_help()
        # sys.exit(-1)
    main(options.src_file)