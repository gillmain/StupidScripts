# fname1 = "C:\\Users\\rmccombs\\Documents\\test.txt"

# with open(fname1) as f:
	# content = f.readlines()
# content = [x.strip() for x in content]

# f1 = open("C:\\Users\\rmccombs\\Documents\\test.txt","r")
# f2 = open("C:\\Users\\rmccombs\\Documents\\test1.txt","r")

with open("C:\\Users\\rmccombs\\Documents\\test.txt","r") as f1:
	for line1 in f1:
		clean1 = line1.strip()
		with open("C:\\Users\\rmccombs\\Documents\\test1.txt","r") as f2:
			for line2 in f2:
				clean2 = line2.strip()
				print clean1 + clean2