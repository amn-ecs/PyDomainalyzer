#!/usr/bin/env python

"""
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

import re
import cPickle
import dns
from dns         import resolver, query, zone
from IPy         import IP
from collections import defaultdict
from datetime    import datetime

class Domainalyzer:
    """
    This class is used to load, parse and analyse one or more DNS zones
    (although you'll need at least 2 - forward and reverse - for it to
    be of much use).
    """
    
    ## Forward and reverse IP-based records from DNS

    # Map of A record -> [IP list] from DNS
    a_record_to_ip_map = defaultdict(list)
    ip_to_a_record_map = defaultdict(list)

    # The same for AAAAs
    aaaa_record_to_ip_map = defaultdict(list)
    ip_to_aaaa_record_map = defaultdict(list)

    # Map of PTR IP -> [name list] from DNS (v4 and v6)
    ptr_record_to_name_map = defaultdict(list)
    name_to_ptr_record_map = defaultdict(list)

    ## Forward and reverse CNAME records from DNS (aliases)

    # Map of CNAME -> name from DNS
    forward_cname_map = defaultdict(list)
    reverse_cname_map = defaultdict(list)


    ## Generated forward and reverse entries ignoring the source record type

    # Reverse map of IP -> [list of names] built from CNAMES, As and AAAAs
    ip_to_all_names_map = defaultdict(list)

    # Map of hostname (from any source record) -> [IP list]
    name_to_all_ip_map = defaultdict(list)

    # Date/time at which the DNS info was processed
    processed_at = None
 
    # List of the domain names we actually know about
    known_domains = []

    def __init__(self, server=None, domains=None, rzones=None):
        """
        Initialises, optionally with lists of forward and reverse zones.
        """

        if server:
            print "Loading from %s" % server
            if domains:
                self.add_forward_zones(server, domains)
            if rzones:
                self.add_reverse_zones(server, rzones)

        self.processed_at = datetime.now()

    def add_forward_zones(self, server, domains):
        """
        Requests zone transfer(s) from the specified DNS server of every forward
        zone we're interested in, and builds internal mapping tables. 
        """

        # Build mappings for the forward DNS zones
        for domain_name in domains:
            print "Transferring %s" %domain_name

            # Do a zone transfer from the master DNS server
            try:
                zone = dns.zone.from_xfr(dns.query.xfr(server, domain_name), relativize=False)
            except:
                import sys
                print "Failed to load "+domain_name+": "+str(sys.exc_info())

                continue
            self._map_forward_zone(zone, domain_name)
        
        self.processed_at = datetime.now()
        
    def add_reverse_zones(self, server, rzones):
        """
        Requests zone transfer(s) from the specified DNS server of every
        reverse zone we're interested in, and builds internal mapping tables. 
        """

        # Build mappings for the reverse DNS zones
        for rzone_name in rzones:

            # We need to know if it's an IPv6 zone or not for building the mappings later
            is_v6 = False

            # IPv4 reverse zones are e.g. 23.168.192.IN-ADDR.ARPA for the 192.168.23.* range
            # Get the IP address parts and reverse them to get the IP prefix
            if(re.search(r'\.IN-ADDR\.ARPA', rzone_name)):

                # Convert "23.168.192.IN-ADDR.ARPA" to "23.168.192"
                ip_prefix = re.sub(r'\.IN-ADDR\.ARPA', '', rzone_name)

                # Convert "23.168.192" to [23, 78, 152]
                parts     = ip_prefix.split('.')

                # Convert to "192.168.23"
                parts.reverse()
                ip_prefix = '.'.join(parts)


            # IPv6 reverse zones are e.g. 8.0.8.0.1.1.e.f.f.3.IP6.ARPA or deprecated .IP6.INT
            # Get the IP address parts and reverse them to get the IP prefix, converting to colon-separated
            elif(re.search(r'\.IP6\.(ARPA|INT)', rzone_name)):

                is_v6 = True

                # Convert "8.0.8.0.1.1.e.f.f.3.IP6.ARPA" to "8.0.8.0.1.1.e.f.f.3"
                ip_prefix = re.sub(r'\.IP6\.(ARPA|INT)', '', rzone_name)

                # Reverse the string (we can do this as each part is a single character)
                # Convert to "3.f.f.e.1.1.0.8.0.8"
                ip_prefix = ip_prefix[::-1]

                # Convert to "3ffe110808"
                ip_prefix = re.sub(r'\.', '', ip_prefix)


            try:
                query = dns.query.xfr(server, rzone_name)
                rzone = dns.zone.from_xfr(query, relativize=False)
            except:
                #print "Failed to process zone "+rzone_name
                continue

            # Now we've done all that hairy stuff, build the mappings
            self._map_reverse_zone(rzone, is_v6, ip_prefix)

        self.processed_at = datetime.now()





    def _map_forward_zone(self, zone, domain_name):
        """
        Given a forward DNS zone, build internal mappings of A/AAAA
        records to IPv4/IPv6 addresses, reverse mappings of the IPs
        to names, mappings of CNAME -> name, and reverse mappings
        of name -> CNAME.

        Maps the forward and reverse CNAME entries FIRST, so as it
        goes along it can also add CNAME entries to the reverse IP maps.
        This means we can end up with a mapping of
        IP -> all hostnames that resolve to this IP.
        This is rather useful!
        """

        # Map CNAME -> name and back
        for (name, ttl, rdata) in zone.iterate_rdatas('CNAME'):

            # Fully qualify the domain names
            from_name = (str(name)+'.'+domain_name).lower()
            to_name   = (str(rdata.target)+'.'+domain_name).lower()

            self.forward_cname_map[from_name] = to_name
            self.reverse_cname_map[to_name].append(from_name)

        # Build map of A => IP and back
        for (name, ttl, rdata) in zone.iterate_rdatas('A'):
            # Fully qualify the domain names
            from_name = (str(name)+'.'+domain_name).lower()
            to_ip   = str(rdata.address)

            # Add to A record map
            self.a_record_to_ip_map[from_name].append(to_ip)
            self.ip_to_a_record_map[to_ip].append(from_name)

            # Add forward and reverse entries to general name and IP maps
            self.ip_to_all_names_map[to_ip].append(from_name)
            self.name_to_all_ip_map[from_name].append(to_ip)

            # Loop over all the CNAMEs for this A record and
            # add general forward/reverse entries
            for cname in self.reverse_cname_map[from_name]:
                self.ip_to_all_names_map[to_ip].append(cname)
                self.name_to_all_ip_map[cname].append(to_ip)


        # Map AAAA -> IP
        for (name, ttl, rdata) in zone.iterate_rdatas('AAAA'):

            # Fully qualify the domain names
            from_name = (str(name)+'.'+domain_name).lower()
            to_ip     = str(rdata.address)

            # Minimise address using IPy
            to_ip     = str(IP(to_ip))

            # Add to AAAA record map
            self.aaaa_record_to_ip_map[from_name].append(to_ip)
            self.ip_to_aaaa_record_map[to_ip].append(from_name)
        
            # Add forward and reverse entries to general name and IP maps
            self.ip_to_all_names_map[to_ip].append(from_name)
            self.name_to_all_ip_map[from_name].append(to_ip)

            for cname in self.reverse_cname_map[from_name]:
                self.name_to_all_ip_map[cname].append(to_ip)
                self.ip_to_all_names_map[to_ip].append(cname)

        self.known_domains.append(domain_name)

    def _map_reverse_zone(self, rzone, is_v6, ip_prefix):
        """
        Given a reverse DNS zone, build internal mappings of PTR records
        to IPv4/IPv6 addresses
        """

        for (name, ttl, rdata) in rzone.iterate_rdatas('PTR'):
            from_ip = str(name)
            to_name = re.sub(r'\.$', '', str(rdata.target).lower())


            # IPv4 address - e.g. 132.23 in 168.192.IN-ADDR.ARPA, prefix is 192.168
            # Expected result: 192.168.23.132
            if(not is_v6):

                # Convert "132.32" to [32, 132]
                parts = from_ip.split('.')
                parts.reverse()

                # Stick on the prefix and join with dots to give "192.168.32.132"
                from_ip = ip_prefix + '.' + '.'.join(parts)


            # IPv6 address - e.g. f.e.1.2.3.4.1.2.3.4.1.2.3.4.1.2.3.4.1.2.3.4
            # in 8.0.8.0.1.1.e.f.f.3.IP6.ARPA
            else:

                # Convert "f.e.1.2.3.4.1.2.3.4.1.2.3.4.1.2.3.4.1.2.3.4"
                # to      "4.3.2.1.4.3.2.1.4.3.2.1.4.3.2.1.4.3.2.1.e.f"
                # by reversing string
                from_ip = from_ip[::-1]

                # Stick on the prefix and remove all dots to give
                # "3ffe11080843214321432143214321ef"
                from_ip = ip_prefix + re.sub(r'\.', '', from_ip)

                # Convert to colon-separated 4 char sequences to give
                # "3ffe:1108:0843:2143:2143:2143:2143:21ef:"
                from_ip = re.sub(r'(....)', r'\1:', from_ip)

                # Remove colon from the end to give "3ffe:1108:0843:2143:2143:2143:2143:21ef"
                from_ip = re.sub(r':$', '', from_ip)

                # Minimise address using IPy to give "3ffe:1108:843:2143:2143:2143:2143:21ef"
                # NB this just gives us a standard minimised representation
                # of all IPv6 addresses, for easy comparison
                from_ip = str(IP(from_ip))

                    

            # Add the PTR mapping of IP -> [name list]
            self.ptr_record_to_name_map[from_ip].append(to_name)
            self.name_to_ptr_record_map[to_name].append(from_ip)


    def __getstate__(self):
        """
        For pickling purposes - returns a list of all the internal mappings we have built.
        """
        return [
          self.a_record_to_ip_map,
          self.ip_to_a_record_map,
          self.aaaa_record_to_ip_map,
          self.ip_to_aaaa_record_map,
          self.forward_cname_map,
          self.reverse_cname_map,
          self.ptr_record_to_name_map,
          self.name_to_ptr_record_map,
          self.name_to_all_ip_map,
          self.ip_to_all_names_map,
          self.processed_at,
          self.known_domains,
        ]

    def __setstate__(self, state):
        """
        For unpickling purposes - populates our internal mappings with data loaded from a pickle.
        """
        self.a_record_to_ip_map     = state[0]
        self.ip_to_a_record_map     = state[1]
        self.aaaa_record_to_ip_map  = state[2]
        self.ip_to_aaaa_record_map  = state[3]
        self.forward_cname_map      = state[4]
        self.reverse_cname_map      = state[5]
        self.ptr_record_to_name_map = state[6]
        self.name_to_ptr_record_map = state[7]
        self.name_to_all_ip_map     = state[8]
        self.ip_to_all_names_map    = state[9]
        self.processed_at           = state[10]
        self.known_domains          = state[11]

    def findProblems(self):
        """
        Finds problems in the DNS records - specifically, missing PTR records and
        PTRs that don't point at one of the correct forward entries.
        """

        problems = []

        for ip in self.ptr_record_to_name_map.keys():

            # Get PTR record(s) for IP
            for ptr in self.ptr_record_to_name_map[ip]:
                
                # If the PTR points at a domain we don't know about, don't complain,
                # we have no way of telling whether it's correct
                ptr_domain = re.sub(r'^[^\.]+\.', '', ptr)
                if ptr_domain not in self.known_domains:
                    continue

                try:
                    ok = False
                    # Check all forward entries that point to this IP
                    for maps_to in self.ip_to_all_names_map[ip]:
                        if(maps_to == ptr):
                            ok = True
                            break

                    # Didn't find one in the list - we have one or more forward records, but none of them match the PTR
                    if(not ok):
                        problems.append("PTR for IP "+ip+" ("+ptr+") has no corresponding forward DNS entry - records are: "+','.join(self.ip_to_all_names_map[ip]))

                # No forward DNS entry at all
                except KeyError:
                    problems.append("PTR for IP "+ip+" ("+ptr+") has no forward DNS entry (A or AAAA)")

        return problems



    def lookupByHostname(self, hostname):
        """
        Given a hostname, returns everything we know about it
        from our DNS info.
        """

        # Convert to lowercase for searching, and remove any whitespace padding
        hostname = hostname.lower()
        hostname = re.sub(r'^\s*(\S+)\s*$', r'\1', hostname)

        # Find any entries we have for the hostname in any of our maps
        a_records = None
        if hostname in self.a_record_to_ip_map:
            a_records = self.a_record_to_ip_map[hostname]

        aaaa_records = None
        if hostname in self.aaaa_record_to_ip_map:
            aaaa_records = self.aaaa_record_to_ip_map[hostname]

        ip_list = None
        if hostname in self.name_to_all_ip_map:
            ip_list = self.name_to_all_ip_map[hostname]

        cname_to = None
        if hostname in self.forward_cname_map:
            cname_to = self.forward_cname_map[hostname]

        cname_from_list = None
        if hostname in self.reverse_cname_map:
            cname_from_list = self.reverse_cname_map[hostname]

        ptr_list = None
        if hostname in self.ptr_record_to_name_map:
            ptr_list = self.ptr_record_to_name_map[hostname]

        # This is the "CNAME with" list - i.e. if this is a CNAME,
        # what else is CNAMEd to the same real hostname?
        cname_with_list = None
        if cname_to:
            cname_with_list = self.reverse_cname_map[cname_to]

        return {
          'A_LIST'         : a_records,
          'AAAA_LIST'      : aaaa_records,
          'IP_LIST'        : ip_list,
          'CNAME_TO'       : cname_to,
          'CNAME_FROM_LIST': cname_from_list,
          'CNAME_WITH_LIST': cname_with_list,
          'PTR_LIST'       : ptr_list,
        }

    def lookupByIP(self, ip):
        """
        Searches for an IP address and returns everything we know about it
        from our DNS info.  Supports IPv4 and IPv6.
        """
        ip = re.sub(r'^\s*(\S+)\s*$', r'\1', ip)

        a_records = None
        if ip in self.ip_to_a_record_map:
            a_records = self.ip_to_a_record_map[ip]

        aaaa_records = None
        if ip in self.ip_to_aaaa_record_map:
            aaaa_records = self.ip_to_aaaa_record_map[ip]

        ptr_records = None
        if ip in self.ptr_record_to_name_map:
            ptr_records = self.ptr_record_to_name_map[ip]

        name_list = None
        if ip in self.ip_to_all_names_map:
            name_list = self.ip_to_all_names_map[ip]

        return{
          'A_LIST'    : a_records,
          'AAAA_LIST' : aaaa_records,
          'PTR_LIST'  : ptr_records,
          'NAME_LIST' : name_list,
        }
        
