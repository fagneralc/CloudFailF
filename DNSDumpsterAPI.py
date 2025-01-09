from __future__ import print_function
from dotenv import load_dotenv
import os
import requests
import re
import sys
import base64

from bs4 import BeautifulSoup


class DNSDumpsterAPI(object):

    """DNSDumpsterAPI Main Handler"""

    def __init__(self, verbose=False):
        self.verbose = verbose
        load_dotenv()
        self.api_key = os.getenv('DNSDUMPSTER_API_KEY')

    def display_message(self, s):
        if self.verbose:
            print('[verbose] %s' % s)

    def retrieve_results(self, table):
        res = []
        trs = table.findAll('tr')
        for tr in trs:
            tds = tr.findAll('td')
            pattern_ip = r'([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})'
            try:
                ip = re.findall(pattern_ip, tds[1].text)[0]
                domain = str(tds[0]).split('<br/>')[0].split('>')[1].split('<')[0]
                header = ' '.join(tds[0].text.replace('\n', '').split(' ')[1:])
                reverse_dns = tds[1].find('span', attrs={}).text

                additional_info = tds[2].text
                country = tds[2].find('span', attrs={}).text
                autonomous_system = additional_info.split(' ')[0]
                provider = ' '.join(additional_info.split(' ')[1:])
                provider = provider.replace(country, '')
                data = {'domain': domain,
                        'ip': ip,
                        'reverse_dns': reverse_dns,
                        'as': autonomous_system,
                        'provider': provider,
                        'country': country,
                        'header': header}
                res.append(data)
            except:
                pass
        return res

    def retrieve_txt_record(self, table):
        res = []
        for td in table.findAll('td'):
            res.append(td.text)
        return res


    def search(self, domain):
        api_key = os.getenv('DNSDUMPSTER_API_KEY')
        if not api_key:
            print("DNSDUMPSTER_API_KEY environment variable not set", file=sys.stderr)
            return []

        api_url = f'https://api.dnsdumpster.com/domain/{domain}'
        headers = {'X-API-Key': api_key}
        
        req = requests.get(api_url, headers=headers)
        if req.status_code != 200:
            print(
                "Unexpected status code from {url}: {code}".format(
                    url=api_url, code=req.status_code),
                file=sys.stderr,
            )
            return []

        try:
            data = req.json()
        except:
            print("Failed to parse JSON response", file=sys.stderr)
            return []

        res = {}
        res['domain'] = domain
        res['dns_records'] = {
            'dns': self._process_records(data.get('a', [])),
            'mx': self._process_records(data.get('mx', [])),
            'txt': data.get('txt', []),
            'host': self._process_records(data.get('ns', []))
        }

        res['image_data'] = base64.b64decode(data['map']) if 'map' in data else None
        res['xls_data'] = None

        return res

    def _process_records(self, records):
        results = []
        for record in records:
            for ip_data in record.get('ips', []):
                results.append({
                    'domain': record.get('host', ''),
                    'ip': ip_data.get('ip', ''),
                    'reverse_dns': ip_data.get('ptr', ''),
                    'as': ip_data.get('asn', ''),
                    'provider': ip_data.get('asn_name', ''),
                    'country': ip_data.get('country', ''),
                    'header': ''
                })
        return results
