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

import dns.resolver, dns.query, dns.zone
import re
import cPickle
from IPy import IP

class Domainalyzer:
    """
    This class is used to load, parse and analyse one or more DNS zones
    (although you'll need at least 2 - forward and reverse - for it to
    be of much use).
    """
    
    ## Forward and reverse IP-based records from DNS

    # Map of A record -> [IP list] from DNS
    forward_a_map = {}

    # The same for AAAAs
    forward_aaaa_map = {}

    # Map of PTR IP -> [name list] from DNS (v4 and v6)
    reverse_ptr_map = {}

    ## Forward and reverse CNAME records from DNS (aliases)

    # Map of CNAME -> name from DNS
    forward_cname_map = {}

    # Reverse map of name -> CNAME built from CNAMES
    reverse_cname_map = {}


    ## Generated forward and reverse entries ignoring the source record type

    # Reverse map of IP -> [list of names] built from CNAMES, As and AAAAs
    reverse_ip_map = {}

    # Map of hostname (from any source record) -> [IP list]
    forward_name_map = {}

    
    def __init__(self, server, domains, rzones):
        """
        Requests zone transfer(s) from the specified DNS server of every forward
        and reverse zone we're interested in, and builds internal mapping tables. 
        """

        # Build mappings for the forward DNS zones
        for domain_name in domains:

            print "Domain: "+domain_name

            # Do a zone transfer from the master DNS server
            try:
                zone = dns.zone.from_xfr(dns.query.xfr(server, domain_name), relativize=False)
            except:
                print "Failed to load "+domain_name
                continue
            self.map_forward_zone(zone, domain_name)
        
        # Build mappings for the reverse DNS zones
        for rzone_name in rzones:

            print "Reverse zone: "+rzone_name

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
                print "Failed to process zone "+rzone_name
                continue

            # Now we've done all that hairy stuff, build the mappings
            self.map_reverse_zone(rzone, is_v6, ip_prefix)






    def map_forward_zone(self, zone, domain_name):
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
            try:
                tmp = self.reverse_cname_map[to_name]
            except KeyError:
                tmp = []
                self.reverse_cname_map[to_name] = tmp
            tmp.append(from_name)

        # Build map of A => IP and back
        for (name, ttl, rdata) in zone.iterate_rdatas('A'):
            # Fully qualify the domain names
            from_name = (str(name)+'.'+domain_name).lower()
            to_name   = str(rdata.address)

            try:
                tmp = self.forward_a_map[from_name]
            except KeyError:
                tmp = []
                self.forward_a_map[from_name] = tmp

            tmp.append(to_name)

            try:
                tmp_ip = self.reverse_ip_map[to_name]
            except KeyError:
                tmp_ip = []
                self.reverse_ip_map[to_name] = tmp_ip
        
            tmp_ip.append(from_name)

            try:
                tmp_name = self.forward_name_map[from_name]
            except KeyError:
                tmp_name = []
                self.forward_name_map[from_name] = tmp_name

            tmp_name.append(to_name)

            try:
                for cname in self.reverse_cname_map[from_name]:
                    tmp_ip.append(cname)
                    try:
                        tmp = self.forward_name_map[cname]
                    except KeyError:
                        tmp = []
                        self.forward_name_map[cname] = tmp
                    tmp.append(to_name)

            except KeyError:
                pass

        # Map AAAA -> IP
        for (name, ttl, rdata) in zone.iterate_rdatas('AAAA'):

            # Fully qualify the domain names
            from_name = (str(name)+'.'+domain_name).lower()
            to_name   = str(rdata.address)

            # Minimise address using IPy
            to_name = str(IP(to_name))

            try:
                tmp = self.forward_aaaa_map[from_name]
            except KeyError:
                tmp = []
                self.forward_aaaa_map[from_name] = tmp

            tmp.append(to_name)
        
            try:
                tmp_ip = self.reverse_ip_map[to_name]
            except KeyError:
                tmp_ip = []
                self.reverse_ip_map[to_name] = tmp_ip

            tmp_ip.append(from_name)

            try:
                tmp_name = self.forward_name_map[from_name]
            except KeyError:
                tmp_name = []
                self.forward_name_map[from_name] = tmp_name

            tmp_name.append(to_name)

            try:
                for cname in self.reverse_cname_map[from_name]:
                    tmp.append(cname.lower())
                    try:
                        tmp = self.forward_name_map[cname]
                    except KeyError:
                        tmp = []
                        self.forward_name_map[cname] = tmp
                    tmp.append(to_name)
            except KeyError:
                pass


    def map_reverse_zone(self, rzone, is_v6, ip_prefix):
        """
        Given a reverse DNS zone, build internal mappings of PTR records
        to IPv4/IPv6 addresses
        """

        for (name, ttl, rdata) in rzone.iterate_rdatas('PTR'):
            from_name = str(name)
            to_name   = re.sub(r'\.$', '', str(rdata.target).lower())


            # IPv4 address - e.g. 132.23 in 168.192.IN-ADDR.ARPA, prefix is 192.168
            # Expected result: 192.168.23.132
            if(not is_v6):

                # Convert "132.32" to [32, 132]
                parts = from_name.split('.')
                parts.reverse()

                # Stick on the prefix and join with dots to give "192.168.32.132"
                from_name = ip_prefix + '.' + '.'.join(parts)


            # IPv6 address - e.g. f.e.1.2.3.4.1.2.3.4.1.2.3.4.1.2.3.4.1.2.3.4
            # in 8.0.8.0.1.1.e.f.f.3.IP6.ARPA
            else:

                # Convert "f.e.1.2.3.4.1.2.3.4.1.2.3.4.1.2.3.4.1.2.3.4"
                # to      "4.3.2.1.4.3.2.1.4.3.2.1.4.3.2.1.4.3.2.1.e.f"
                # by reversing string
                from_name = from_name[::-1]

                # Stick on the prefix and remove all dots to give
                # "3ffe11080843214321432143214321ef"
                from_name = ip_prefix + re.sub(r'\.', '', from_name)

                # Convert to colon-separated 4 char sequences to give
                # "3ffe:1108:0843:2143:2143:2143:2143:21ef:"
                from_name = re.sub(r'(....)', r'\1:', from_name)

                # Remove colon from the end to give "3ffe:1108:0843:2143:2143:2143:2143:21ef"
                from_name = re.sub(r':$', '', from_name)

                # Minimise address using IPy to give "3ffe:1108:843:2143:2143:2143:2143:21ef"
                # NB this just gives us a standard minimised representation
                # of all IPv6 addresses, for easy comparison
                from_name = str(IP(from_name))

                    

            # Add the PTR mapping of IP -> [name list]
            try:
                tmp = self.reverse_ptr_map[from_name]
            except KeyError:
                tmp = []
                self.reverse_ptr_map[from_name] = tmp
            
            tmp.append(to_name)


    def __getstate__(self):
        """
        For pickling purposes - returns a list of all the internal mappings we have built.
        """
        return [
          self.forward_a_map,
          self.forward_aaaa_map,
          self.forward_cname_map,
          self.forward_name_map,
          self.reverse_cname_map,
          self.reverse_ptr_map,
          self.reverse_ip_map
        ]

    def __setstate__(self, state):
        """
        For unpickling purposes - populates our internal mappings with data loaded from a pickle.
        """
        self.forward_a_map     = state[0]
        self.forward_aaaa_map  = state[1]
        self.forward_cname_map = state[2]
        self.forward_name_map  = state[3]
        self.reverse_cname_map = state[4]
        self.reverse_ptr_map   = state[5]
        self.reverse_ip_map    = state[6]


    def findProblems(self):
        """
        Finds problems in the DNS records - specifically, missing PTR records and
        PTRs that don't point at one of the correct forward entries.
        """

        problems = []

        for ip in self.reverse_ptr_map.keys():
            # Get PTR record for IP
            ptr = self.reverse_ptr_map[ip]

            try:
                ok = False
                # Check all forward entries that point to this IP
                for maps_to in self.reverse_ip_map[ip]:
                    if(maps_to == ptr):
                        ok = True
                        break

                # Didn't find one in the list - we have one or more forward records, but none of them match the PTR
                if(not ok):
                    problems.append("PTR for IP "+ip+" ("+ptr+") has no corresponding forward DNS entry - records are: "+','.join(self.reverse_ip_map[ip]))

            # No forward DNS entry at all
            except KeyError:
                problems.append("PTR for IP "+ip+" ("+ptr+") has no forward DNS entry (A or AAAA)")

        return problems


    def searchByHostname(self, search_term):
        """
        Searches for a hostname and returns everything we know about it
        from our DNS info.
        """

        # Convert to lowercase for searching, and remove any whitespace padding
        hostname = search_term.lower()
        hostname = re.sub(r'^\s*(\S+)\s*$', r'\1', hostname)

        a_records = None
        if hostname in self.forward_a_map:
            a_records = self.forward_a_map[hostname]

        aaaa_records = None
        if hostname in self.forward_aaaa_map:
            aaaa_records = self.forward_aaaa_map[hostname]

        ip_list = None
        if hostname in self.forward_name_map:
            ip_list = self.forward_name_map[hostname]

        cname_to_list = None
        if hostname in self.forward_cname_map:
            cname_to_list = self.forward_cname_map[hostname]

        cname_from_list = None
        if hostname in self.reverse_cname_map:
            cname_from_list = self.reverse_cname_map[hostname]

        ptr_list = None
        if hostname in self.reverse_ptr_map:
            ptr_list = self.reverse_ptr_map[hostname]

        return {
          'A'         : a_records,
          'AAAA'      : aaaa_records,
          'IP_LIST'   : ip_list,
          'CNAME_TO'  : cname_to_list,
          'CNAME_FROM': cname_from_list,
          'PTR'       : ptr_list,
        }

    def searchByIP(self, search_term):
        """
        Searches for an IP address and returns everything we know about it
        from our DNS info.  Supports IPv4 and IPv6.
        """
        pass
        
