==============
PyDomainalyzer
==============

DNS analysis library/tool written in Python

This library is a tool for extracting information from one or more DNS servers (via XFER queries) and analysing the results.  Essentially, if host A is a DNS server and host B is allowed to XFER zones from it, host B can run PyDomainalyzer against host A and check for possible problems (e.g. unmatched PTR/A records).

It is also useful for finding all possible hostnames that refer to a specific IP, including CNAMES and additional A/AAAA records.


Dependencies
============

* IPy
* dnspython

Quick example
=============

Before using:

* Ensure you have all dependencies installed
* Make sure you can perform zone transfers from a DNS server which knows about all the domains you're interested in!

I'll assume you're talking to ns0.example.org from a machine that can do zone transfers from it.
Your domains are example.org and example.com, and you're using 192.168.1.0/24, 192.168.2.0/24
and 2001:DB8:beef::/64.

	#!/usr/bin/env python
	
	from domainalyzer import Domainalyzer
	from pprint import pprint
	
	# Who to talk to
	server  = 'ns0.example.org'
	
	# Forward DNS domains
	domains = ['example.org', 'example.com']
	
	# Reverse DNS domains
	rdoms   = ['1.168.192.IN-ADDR.ARPA', '2.168.192.IN-ADDR.ARPA', 'f.e.e.b.8.b.d.0.1.0.0.2.IP6.INT']
	
	# Let's get started...
	analyzer = Domainalyzer(server, domains, rdoms)
	
	
	print "Finding foo.example.org..."
	found = analyzer.lookupByHostname('foo.example.org')
	pprint(found)
	
	# Leading/trailing whitespace is stripped and hostname is lowercased
	print "Finding spam.example.com..."
	found = analyzer.lookupByHostname('  SPAM.example.COM     ')
	pprint(found)
	
	print "Finding 192.168.1.71..."
	found = analyzer.lookupByIP('  192.168.1.71  ')
	pprint(found)
	
	print "Looking for problems..."
	problems = analyzer.findProblems()
	pprint(problems)


The Domainalyzer object is compatible with Python's pickle system,
so it's perfectly possible to do a big pile of zone transfers, then
pickle the object to a file for speedier lookups.  You'd have to
periodically refresh the pickled object of course...

Known problems and limitations
==============================

Currently, the findProblems function whinges about missing A/AAAA records for
PTRs that point to domains it does not know about (e.g. if you have a PTR
from 192.168.1.2 to zebra.example.net, but you don't have access to the
example.net DNS zones, it'll complain).

There's no search function, only exact lookup functions.

findProblems doesn't do a lot of checking yet.

TODO list
=========

This started out as a hacked-together script that I've refactored a bit to make
it more sane, however it's still got room for improvement :-)

* Instead of __init__ taking lists of Things To Know About, write add() functions to add new zones


