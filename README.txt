How to run the program:
1. If necessary, change the filename to whatever pcap file you would like to analyze
2. Press run
3. Terminal output will showcase details regarding the ARP request and reply
4. Output includes hardware and protocol type/size, opcode, sender and target MAC/IP addresses

How the program works:
1. PCAP file is opened and read with dpkt from lines 8-11
2. Main function loops through the pcap object and filters out non-arp packets based on bytes from bytes 12/13
	2a. If opcode matches with 0001, current packet assigned as request (skips announcements based on first 6 bytes)
	2b. If opcode matches with 0002, current packet assigned as reply 
3. Main prints out headers for output, and calls printInfo function to print information
4. printInfo formats and prints all information for a specific packet from parameter
	4a. Hardware and protocol type/size and opcode are grabbed directly from bytes and converted with .hex()
	4b. Sender/Target MAC addresses converted with .hex(':') to divide bits by colons
	4c. Sender/Target IP addresses first converted to ints, then packed to 32 bit with struct.pack, and finally
	    converted to IP address with socket.inet_ntoa()