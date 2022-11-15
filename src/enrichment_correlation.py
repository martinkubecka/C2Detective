import time
import logging

class EnrichmentCorrelation:
    def __init__(self, target, abuseipdb, securitytrails, virustotal, shodan, alienvault, bgp_ranking):
        self.logger = logging.getLogger(__name__)
        self.target = target
        self.abuseipdb = abuseipdb
        self.securitytrails = securitytrails
        self.virustotal = virustotal
        self.shodan = shodan
        self.alienvault = alienvault
        self.bgp_ranking = bgp_ranking

    def enrichment_correlation(self):

        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Correlating enriched data ...")
        self.logger.info(f"Correlating enriched data ...")

        extracted_data = {}
        extracted_data['target'] = self.target

        if self.abuseipdb:
            country_code = self.abuseipdb['data']['countryCode'] # e.g. SK
            usage_type = self.abuseipdb['data']['usageType'] # e.g. University/College/School
            isp = self.abuseipdb['data']['isp']  # e.g. Slovak Technical University
            total_reports = self.abuseipdb['data']['totalReports']   # e.g. 0
            last_reported = self.abuseipdb['data']['lastReportedAt'] # e.g. None
            # print(self.abuseipdb['data']['countryCode'])
            # print(self.abuseipdb['data']['usageType'])
            # print(self.abuseipdb['data']['isp'])
            # print(self.abuseipdb['data']['totalReports'])
            # print(self.abuseipdb['data']['lastReportedAt'])  # may be 'null' then returns None

            abuseipdb = {}
            abuseipdb['total_reports'] = total_reports
            abuseipdb['last_reported'] = last_reported
            extracted_data['abuseipdb'] = abuseipdb

        if securitytrails:
            current_dns = securitytrails[0]['current_dns']
            current_dns_a_record = current_dns['a']
            current_dns_aaaa_record = current_dns['aaaa']
            current_dns_mx_record = current_dns['mx']
            current_dns_ns_record = current_dns['ns']
            current_dns_soa_record = current_dns['soa']
            current_dns_txt_record = current_dns['txt']

            if current_dns_a_record:
                first_seen = dict(
                    first_seen=current_dns_a_record['first_seen'])
                values = current_dns_a_record['values']
                entries = []
                data = {}
                for entry in values:
                    ip = entry['ip']
                    ip_organization = entry['ip_organization']
                    data = dict(
                        ip=ip,
                        ip_organization=ip_organization)
                    entries.append(data)

            current_dns_a_record = []
            current_dns_a_record.append(first_seen)
            current_dns_a_record.append(entries)

            if current_dns_aaaa_record:
                first_seen = dict(
                    first_seen=current_dns_aaaa_record['first_seen'])
                values = current_dns_aaaa_record['values']
                entries = []
                data = {}
                for entry in values:
                    ip = entry['ipv6']
                    ip_organization = entry['ipv6_organization']
                    data = dict(
                        ipv6=ip,
                        ipv6_organization=ip_organization)
                    entries.append(data)

            current_dns_aaaa_record = []
            current_dns_aaaa_record.append(first_seen)
            current_dns_aaaa_record.append(entries)

            if current_dns_mx_record:   # FIND TARGET WITH MX RECORD !
                print()

            current_dns_mx_record = []
            # current_dns_mx_record.append(first_seen)
            # current_dns_mx_record.append(entries)
            
            if current_dns_ns_record:
                first_seen = dict(
                    first_seen=current_dns_ns_record['first_seen'])
                values = current_dns_ns_record['values']
                entries = []
                data = {}
                for entry in values:
                    nameserver = entry['nameserver']
                    nameserver_organization = entry['nameserver_organization']
                    data = dict(
                        nameserver=nameserver,
                        nameserver_organization=nameserver_organization)
                    entries.append(data)

            current_dns_ns_record = []
            current_dns_ns_record.append(first_seen)
            current_dns_ns_record.append(entries)

            if current_dns_soa_record:
                first_seen = dict(
                    first_seen=current_dns_soa_record['first_seen'])
                values = current_dns_soa_record['values']
                entries = []
                data = {}
                for entry in values:
                    email = entry['email']
                    data = dict(
                        email=email)
                    entries.append(data)

            current_dns_soa_record = []
            current_dns_soa_record.append(first_seen)
            current_dns_soa_record.append(entries)

            if current_dns_txt_record:
                first_seen = dict(
                    first_seen=current_dns_txt_record['first_seen'])
                values = current_dns_txt_record['values']
                entries = []
                data = {}
                for entry in values:
                    value = entry['value']
                    data = dict(
                        value=value)
                    entries.append(data)

            current_dns_txt_record = []
            current_dns_txt_record.append(first_seen)
            current_dns_txt_record.append(entries)


            securitytrails = {}
            # securitytrails['current_dns'] = current_dns
            securitytrails['current_dns_a_record'] = current_dns_a_record
            securitytrails['current_dns_aaaa_record'] = current_dns_aaaa_record
            securitytrails['current_dns_mx_record'] = current_dns_mx_record
            securitytrails['current_dns_ns_record'] = current_dns_ns_record
            securitytrails['current_dns_soa_record'] = current_dns_soa_record
            securitytrails['current_dns_txt_record'] = current_dns_txt_record

            extracted_data['securitytrails'] = securitytrails

        if self.virustotal:
            virustotal_report = self.virustotal[0]
            virustotal_scans_report = self.virustotal[1]
            scan_date = virustotal_scans_report['scan_date']
            permalink = virustotal_scans_report['permalink']
            positives = virustotal_scans_report['positives']
            total = virustotal_scans_report['total']

            virustotal = {}
            virustotal['scan_date'] = scan_date
            virustotal['permalink'] = permalink
            virustotal['positives'] = positives
            virustotal['total'] = total
            extracted_data['virustotal'] = virustotal
            
        if self.shodan:
            try:
                country_name = self.shodan['country_name']
            except KeyError as e:
                country_name = "N/A"
            try:
                country_code = self.shodan['country_code']
            except KeyError as e:
                country_code = "N/A"
            try:
                city = self.shodan['city']
            except KeyError as e:
                city = "N/A"
            try:
                region_code = self.shodan['region_code']
            except KeyError as e:
                region_code = "N/A"
            try:
                isp = self.shodan['isp']
            except KeyError as e:
                isp = "N/A"
            try:
                asn = self.shodan['asn']
            except KeyError as e:
                asn = "N/A"
            try:
                ports = self.shodan['ports']
            except KeyError as e:
                ports = "N/A"
            try:
                hostnames = self.shodan['hostnames']
            except KeyError as e:
                hostnames = "N/A"
            try:
                domains = self.shodan['domains']
            except KeyError as e:
                domains = "N/A"

            data = self.shodan['data'] # extract {port : {product, version}}
            ports_info = {}
            metadata = {}
            for entry in data:
                try:
                    port = entry['port']
                except KeyError as e:
                    port = "N/A"
                try:
                    product = entry['product']
                except KeyError as e:
                    product = "N/A"                
                try:
                    version = entry['version']
                except KeyError as e:
                    version = "N/A"
                
                metadata = dict(
                    product=product,
                    version=version
                )
                ports_info[port] = metadata    

            try:
                vulns = shodan['vulns']
            except KeyError as e:
                vulns = "N/A"

            # print(self.shodan['country_name'])
            # print(self.shodan['country_code'])
            # print(self.shodan['city'])
            # print(self.shodan['region_code'])
            # print(self.shodan['isp'])
            # print(self.shodan['asn'])
            # print(self.shodan['ports'])
            # print(self.shodan['hostnames'])
            # print(self.shodan['domains'])
            # print(self.shodan['data']) # extract port, product, version
            # print(self.shodan['vulns'])

            shodan = {}
            shodan['country_name'] = country_name
            shodan['country_code'] = country_code
            shodan['city'] = city
            shodan['region_code'] = region_code
            shodan['isp'] = isp
            shodan['asn'] = asn
            shodan['ports'] = ports
            shodan['ports_info'] = ports_info
            shodan['hostnames'] = hostnames
            shodan['domains'] = domains
            shodan['vulns'] = vulns
            extracted_data['shodan'] = shodan
            # extracted_data['country_name'] = country_name
            # extracted_data['country_code'] = country_code
            # extracted_data['city'] = city
            # extracted_data['region_code'] = region_code
            # extracted_data['isp'] = isp
            # extracted_data['asn'] = asn
            # extracted_data['ports'] = ports
            # extracted_data['ports_info'] = ports_info
            # extracted_data['hostnames'] = hostnames
            # extracted_data['domains'] = domains
            # extracted_data['vulns'] = vulns

        if self.alienvault:
            print()
        if self.bgp_ranking:
            print()
        return