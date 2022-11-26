import time
import logging

class EnrichmentCorrelation:
    def __init__(self, target, abuseipdb, threatfox, securitytrails, virustotal, shodan, alienvault, bgp_ranking, urlhaus):
        self.logger = logging.getLogger(__name__)
        self.target = target
        self.abuseipdb = abuseipdb
        self.threatfox = threatfox
        self.securitytrails = securitytrails
        self.virustotal = virustotal
        self.shodan = shodan
        self.alienvault = alienvault
        self.bgp_ranking = bgp_ranking
        self.urlhaus = urlhaus

    def enrichment_correlation(self):
        
        # print(f"[{time.strftime('%H:%M:%S')}] [INFO] Correlating enriched data ...")
        self.logger.info(f"Correlating enriched data ...")

        extracted_data = {}
        extracted_data['target'] = self.target

        if self.abuseipdb:
            data = self.abuseipdb.get('data')
            if data:
                country_code = data.get('countryCode') # e.g. SK
                usage_type = data.get('usageType') # e.g. University/College/School
                isp = data.get('isp')  # e.g. Slovak Technical University
                total_reports = data.get('totalReports')   # e.g. 0
                last_reported = data.get('lastReportedAt') # may be 'null' then returns None
                reports = data.get('reports')
                report_entries = []
                if reports:
                    data = {}
                    for entry in reports:
                        reported_at = entry.get('reportedAt')
                        comment = entry.get('comment')
                        categories = entry.get('categories')
                        data = dict(
                            reported_at=reported_at,
                            comment=comment,
                            categories=categories
                        )
                        report_entries.append(data)

                abuseipdb = {}
                abuseipdb['total_reports'] = total_reports
                abuseipdb['last_reported'] = last_reported
                abuseipdb['reports'] = report_entries
                extracted_data['abuseipdb'] = abuseipdb

        if self.threatfox:
            threatfox_entry = {}
            data = self.threatfox.get('data')   
            if data:
                try:
                    data = data[0] # data": [ { "id": "1337", "ioc": "139.180.203.104:443", ... } ]
                    ioc = data.get('ioc')
                    ioc_type = data.get('ioc_type')
                    ioc_type_desc = data.get('ioc_type_desc')
                    threat_type = data.get('threat_type')
                    threat_type_desc = data.get('threat_type_desc')
                    malware = data.get('malware_printable')
                    malware_malpedia = data.get('malware_malpedia')
                    confidence_level = data.get('confidence_level')
                    first_seen = data.get('first_seen')
                    last_seen = data.get('last_seen')
                    tags = data.get('tags')
                    malware_samples = data.get('malware_samples')

                    threatfox_entry['ioc'] = ioc
                    threatfox_entry['ioc_type'] = ioc_type
                    threatfox_entry['ioc_type_desc'] = ioc_type_desc
                    threatfox_entry['threat_type'] = threat_type
                    threatfox_entry['threat_type_desc'] = threat_type_desc
                    threatfox_entry['malware'] = malware
                    threatfox_entry['malware_malpedia'] = malware_malpedia
                    threatfox_entry['confidence_level'] = confidence_level
                    threatfox_entry['first_seen'] = first_seen
                    threatfox_entry['last_seen'] = last_seen
                    threatfox_entry['tags'] = tags
                    threatfox_entry['malware_samples'] = malware_samples

                    extracted_data['threatfox'] = threatfox_entry
                except IndexError as e:
                                self.logger.error("Threatfox correlation data error", exc_info=True)


        if self.securitytrails:
            securitytrails_entry = {}
            # current_dns
            try:
                current_dns = self.securitytrails[0].get('current_dns')
                
                current_dns_a_record = current_dns.get('a')
                current_dns_aaaa_record = current_dns.get('aaaa')
                current_dns_mx_record = current_dns.get('mx')
                current_dns_ns_record = current_dns.get('ns')
                current_dns_soa_record = current_dns.get('soa')
                current_dns_txt_record = current_dns.get('txt')

                if current_dns_a_record:
                    first_seen = current_dns_a_record.get('first_seen')
                    # first_seen = dict(
                    #     first_seen=current_dns_a_record['first_seen'])
                    values = current_dns_a_record.get('values')
                    entries = []
                    data = {}
                    for entry in values:
                        ip = entry.get('ip')
                        ip_organization = entry.get('ip_organization')
                        data = dict(
                            ip=ip,
                            ip_organization=ip_organization)
                        entries.append(data)
                    current_dns_a_record = {}
                    current_dns_a_record['first_seen'] = first_seen
                    current_dns_a_record['values'] = entries

                if current_dns_aaaa_record:
                    first_seen = current_dns_aaaa_record.get('first_seen')
                    values = current_dns_aaaa_record.get('values')
                    entries = []
                    data = {}
                    for entry in values:
                        ip = entry.get('ipv6')
                        ip_organization = entry.get('ipv6_organization')
                        data = dict(
                            ipv6=ip,
                            ipv6_organization=ip_organization)
                        entries.append(data)
                    current_dns_aaaa_record = {}
                    current_dns_aaaa_record['first_seen'] = first_seen
                    current_dns_aaaa_record['values'] = entries

                if current_dns_mx_record:   # FIND TARGET WITH MX RECORD !
                    print()
                    current_dns_mx_record = []
                    # current_dns_mx_record.append(first_seen)
                    # current_dns_mx_record.append(entries)

                if current_dns_ns_record:
                    first_seen = current_dns_ns_record.get('first_seen')
                    values = current_dns_ns_record.get('values')
                    entries = []
                    data = {}
                    for entry in values:
                        nameserver = entry.get('nameserver')
                        nameserver_organization = entry.get('nameserver_organization')
                        data = dict(
                            nameserver=nameserver,
                            nameserver_organization=nameserver_organization)
                        entries.append(data)
                    current_dns_ns_record = {}
                    current_dns_ns_record['first_seen'] = first_seen
                    current_dns_ns_record['values'] = entries

                if current_dns_soa_record:
                    first_seen = current_dns_soa_record.get('first_seen')
                    values = current_dns_soa_record.get('values')
                    entries = []
                    data = {}
                    for entry in values:
                        email = entry.get('email')
                        data = dict(
                            email=email)
                        entries.append(data)
                    current_dns_soa_record = {}
                    current_dns_soa_record['first_seen'] = first_seen
                    current_dns_soa_record['values'] = entries

                if current_dns_txt_record:
                    first_seen = current_dns_txt_record.get('first_seen')
                    values = current_dns_txt_record.get('values')
                    entries = []
                    data = {}
                    for entry in values:
                        value = entry.get('value')
                        data = dict(
                            value=value)
                        entries.append(data)
                    current_dns_txt_record = {}
                    current_dns_txt_record['first_seen'] = first_seen
                    current_dns_txt_record['values'] = entries

                current_dns = {}
                current_dns['a'] = current_dns_a_record
                current_dns['aaaa'] = current_dns_aaaa_record
                current_dns['mx'] = current_dns_mx_record
                current_dns['ns'] = current_dns_ns_record
                current_dns['soa'] = current_dns_soa_record
                current_dns['txt'] = current_dns_txt_record
                securitytrails_entry['current_dns'] = current_dns
            
            except IndexError as e:
                self.logger.error("SecurityTrails correlation data error", exc_info=True)
            
            # subdomains
            try:
                subdomains = self.securitytrails[1].get('subdomains')
                securitytrails_entry['subdomains'] = subdomains
            except IndexError as e:
                self.logger.error("SecurityTrails correlation data error", exc_info=True) 
            
            # tags
            try:
                tags = self.securitytrails[2].get('tags')
                securitytrails_entry['tags'] = tags
            except IndexError as e:
                self.logger.error("SecurityTrails correlation data error", exc_info=True) 

            extracted_data['securitytrails'] = securitytrails_entry

        if self.virustotal:
            try:
                virustotal_report = self.virustotal[0]
                virustotal_scans_report = self.virustotal[1]
                if virustotal_scans_report:
                    scan_date = virustotal_scans_report.get('scan_date')
                    permalink = virustotal_scans_report.get('permalink')
                    positives = virustotal_scans_report.get('positives')
                    total = virustotal_scans_report.get('total')

                    virustotal = {}
                    virustotal['scan_date'] = scan_date
                    virustotal['permalink'] = permalink
                    virustotal['positives'] = positives
                    virustotal['total'] = total
                    extracted_data['virustotal'] = virustotal
            except IndexError as e:
                self.logger.error("Virustotal data correlation error", exc_info=True)


        if self.shodan:
            country_name = self.shodan.get('country_name')
            country_code = self.shodan.get('country_code')
            city = self.shodan.get('city')
            region_code = self.shodan.get('region_code')
            isp = self.shodan.get('isp')
            asn = self.shodan.get('asn')
            ports = self.shodan.get('ports')
            hostnames = self.shodan.get('hostnames')
            domains = self.shodan.get('domains')

            data = self.shodan.get('data') # extract {port : {product, version}}
            ports_info = {}
            if data:
                metadata = {}
                for entry in data:
                    port = entry.get('port')
                    product = entry.get('product')
                    version = entry.get('version')
                    metadata = dict(
                        product=product,
                        version=version
                    )
                    ports_info[port] = metadata    

            vulns = self.shodan.get('vulns')

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

        if self.alienvault:
            alienvault_entry = {}

            # pulse_info
            try:
                pulse_info = self.alienvault[0].get('pulse_info')
                if pulse_info:
                    references = pulse_info['references']
                    related = pulse_info['related']
                    alienvault_entry['references'] = references
                    alienvault_entry['related'] = related
            except IndexError as e:
                self.logger.error("Alienvault correlation data error", exc_info=True)

            # url_list
            try:
                url_list = self.alienvault[3].get('url_list')    # shows only one page...
                if url_list:
                    url_list_entry = []
                    entry_data = [] 
                    for entry in url_list:
                        date = entry.get('date')
                        url = entry.get('url')
                        hostname = entry.get('hostname')
                        result = entry.get('result')
                        http_code = result.get('urlworker').get('http_code')
                        if not http_code:
                            http_code = 0

                        if not http_code == 0:
                            ip = result.get('urlworker').get('ip')
                        else:
                            ip = None
                        entry_data = dict(
                            date=date,
                            url=url,
                            hostname=hostname,
                            ip=ip,
                            http_code=http_code
                        )
                        url_list_entry.append(entry_data)

                    alienvault_entry['associated_urls'] = url_list_entry
            except IndexError as e:
                self.logger.error("Alenvault correlation data error", exc_info=True)

            # passive_dns
            try:
                passive_dns = self.alienvault[4].get('passive_dns') # shows all entries
                # count = self.alienvault[4]['count']
                if passive_dns:
                    passive_dns_entry = []
                    # passive_dns_entry['count'] = count
                    entry_data = [] 
                    for entry in passive_dns:
                        hostname = entry.get('hostname')
                        record_type = entry.get('record_type')
                        address = entry.get('address')
                        first_seen = entry.get('first')
                        last_seen = entry.get('last')
                        asn = entry.get('asn')
                        country = entry.get('flag_title')
                        entry_data = dict(
                            hostname=hostname,
                            record_type=record_type,
                            address=address,
                            first_seen=first_seen,
                            last_seen=last_seen,
                            asn=asn,
                            country=country
                        )
                        passive_dns_entry.append(entry_data)
                    alienvault_entry['passive_dns'] = passive_dns_entry
            except IndexError as e:
                self.logger.error("Alenvault correlation data error", exc_info=True)

            extracted_data['alienvault'] = alienvault_entry

        if self.bgp_ranking:
            bgp_ranking_entry = {}
            response = self.bgp_ranking.get('response')
            if response:
                asn_description = response.get('asn_description')
                ranking = response.get('ranking')
                rank = ranking.get('rank')
                position = ranking.get('position')
                total_known_asns = ranking.get('total_known_asns')

                bgp_ranking_entry['asn_description'] = asn_description
                bgp_ranking_entry['rank'] = rank
                bgp_ranking_entry['position'] = position
                bgp_ranking_entry['total_known_asns'] = total_known_asns

                extracted_data['bgp_ranking'] = bgp_ranking_entry

        if self.urlhaus:
            urlhaus_entry = {}
            urlhaus_reference = self.urlhaus.get('urlhaus_reference')
            firstseen = self.urlhaus.get('firstseen')
            urls = self.urlhaus.get('urls')
            parsed_urls_data = []
            if urls:
                for entry in urls:
                    urlhaus_reference = entry.get('urlhaus_reference')
                    url  = entry.get('url')
                    url_status = entry.get('url_status') 
                    threat = entry.get('threat')
                    tags = entry.get('tags')
                    data = dict(
                        urlhaus_reference=urlhaus_reference,
                        url=url,
                        url_status=url_status,
                        threat=threat,
                        tags=tags
                    )
                    parsed_urls_data.append(data)

            urlhaus_entry['urlhaus_reference'] = urlhaus_reference
            urlhaus_entry['firstseen'] = firstseen
            urlhaus_entry['urls'] = parsed_urls_data

            extracted_data['urlhaus'] = urlhaus_entry

        return extracted_data