#!/usr/bin/env python
"""
Example tool to demonstrate some usage of the Domainalyzer library.
Loads DNS zones via zone transfer and checks for problems.  cPickle
is used to cache the transferred zones to a local file, which is
automatically refreshed.

This is an example script only; it doesn't do anything clever like
check whether the cache contains every zone we were expecting!
Use with caution!

Licence
=======

The MIT License

Copyright (c) 2012 Andy Newton

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
"""


from domainalyzer import Domainalyzer
from optparse     import OptionParser
from datetime     import datetime, timedelta
import cPickle

parser = OptionParser()
parser.add_option(
  "-s", "--server", "--dns-server", dest="server",
  help="DNS server to transfer zones from",
)
parser.add_option(
  "-f", "--file", dest="filename",
  help="File to cache zones into",
)
parser.add_option(
  "-z", "--fzones", "--forward-zones", dest="fzones",
  help="Comma-separated list of forward DNS zones to transfer",
)
parser.add_option(
  "-r", "--rzones", "--reverse-zones", dest="rzones",
  help="Comma-separated list of reverse DNS zones to transfer",
)
parser.add_option(
  "-m", "--max-age", dest="max_age", type="int", default=5,
  help="Maximum age of cached data until it is refreshed, in minutes - default 5",
)
parser.add_option(
  "-c", "--cache-reload", dest="force_reload", action="store_true",
  help="Force a reload of the cache, even if the cached file is recent",
)
parser.add_option(
  "-d", "--dump", dest="dump", action="store_true",
  help="Dumps all discovered entries to standard output, e.g. for debugging",
)

(options, args) = parser.parse_args()




# Check we've got what we need...
errors = []

if(not options.server):
    errors.append('Must provide a DNS server name or IP address')

if(not options.fzones):
    errors.append('Must provide at least 1 forward DNS zone')

if(not options.rzones):
    errors.append('Must provide at least 1 reverse DNS zone')

if(len(errors) != 0):
    import sys
    print "Error:"
    for err in errors:
        print "* "+err
    sys.exit(1)















def refreshCache():
    """
    Transfers zone files from the server and (if required)
    stores the resulting object to a cache file using cPickle.
    """
    checker = Domainalyzer(options.server, fzones, rzones)
    
    if(options.filename):
        f = open(options.filename, 'w')
        cPickle.dump(checker, f)
        f.close()

    return checker

def loadCache():
    """
    If a cache file is being used, attempt to load a Domainalyzer
    object from the cache.  If it fails, or it's out of date,
    creates a new object and stores back to the cache.
    """

    if(not options.filename):
        return refreshCache()

    try:
        f = open(options.filename, 'r')
        checker = cPickle.load(f)
        f.close()
    
    except IOError:
        checker = None
    
    if(not checker or not checker.processed_at or datetime.now() - checker.processed_at > timedelta(minutes=int(options.max_age))):
        checker = refreshCache()
    
    return checker




# Convert comma-separated zone lists to actual lists
fzones = options.fzones.split(',')
rzones = options.rzones.split(',')

if options.force_reload:
    checker = refreshCache()
else:
    checker = loadCache()

print "Cache last refreshed at "+str(checker.processed_at)

if options.dump:

    print "Dumping A->IPv4 map..."
    for a, ip_list in checker.a_record_to_ip_map.iteritems():
        print "%s: [%s]" % (a, ','.join(ip_list))

    print "Dumping AAAA->IPv6 map..."
    for aaaa, ip_list in checker.aaaa_record_to_ip_map.iteritems():
        print "%s: [%s]" % (aaaa, ','.join(ip_list))

    print "Dumping name->PTR map..."
    for name, ptr_list in checker.name_to_ptr_record_map.iteritems():
        print "%s: [%s]" % (name, ','.join(ptr_list))

    print "Dumping cname->name map..."
    for cname, name in checker.forward_cname_map.iteritems():
        print "%s: [%s]" % (cname, name)

    print "Dumping IPv4->A map..."
    for ip, a_list in checker.ip_to_a_record_map.iteritems():
        print "%s: [%s]" % (ip, ','.join(a_list))

    print "Dumping IPv6->AAAA..."
    for ip, aaaa_list in checker.ip_to_aaaa_record_map.iteritems():
        print "%s: [%s]" % (ip, ','.join(aaaa_list))

    print "Dumping PTR->name map..."
    for ptr, name_list in checker.ptr_record_to_name_map.iteritems():
        print "%s: [%s]" % (ptr, ','.join(name_list))

    print "Dumping name->cname map..."
    for name, cname_list in checker.reverse_cname_map.iteritems():
        print "%s: [%s]" % (name, ','.join(cname_list))



print "Checking for problems..."
for aaagh in checker.findProblems():
    print aaagh
