# dnsreport
get the given hostname dns result from a dns server,support ipv4 and ipv6
c++ linux dns client; use this to test your dns server.
#download and make
git clone https://github.com/zimalworld/dnsreport.git
#
cd ./dnsreport
#
make
#how to use it
./dnsreport 
#input dns server address
Enter dns server : 8.8.4.4
#input Hostname to search
Enter Hostname to Lookup : google.com
#enter to see the result
Resolving google.com
Sending Packet...Done
Receiving answer...Done
The response contains : 
 1 Answers.
 0 Authoritative Servers.
 0 Additional records.


Answer Records : 1 
Name : google.com IPv4 address : 216.58.200.238

Authoritive Records : 0 

Additional Records : 0 
Resolving google.com.
Sending Packet...Done
Receiving answer...Done
The response contains : 
 1 Answers.
 0 Authoritative Servers.
 0 Additional records.


Answer Records : 1 
Name : google.com IPv6 address : 2404:6800:4008:800::200e

Authoritive Records : 0 

Additional Records : 0 


## Donation
If this project help you , you can give me a cup of coffee :) 

[![paypal](https://www.paypalobjects.com/en_US/i/btn/btn_donateCC_LG.gif)](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=UDS9UHMHDWDMY)




