#!/usr/bin/env python3

import urllib.request
import csv
import codecs

# Urls to download manufatures CSV
urls = [
    'https://standards.ieee.org/develop/regauth/oui/oui.csv',
    'https://standards.ieee.org/develop/regauth/oui28/mam.csv',
    'https://standards.ieee.org/develop/regauth/oui36/oui36.csv']

# User-Agent header to mimic a web browser request
user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'

for url in urls:
    request = urllib.request.Request(url, headers={'User-Agent': user_agent})
    try:
        url_fetcher = urllib.request.urlopen(request)
        reader = csv.DictReader(codecs.iterdecode(url_fetcher, 'utf-8'))
        with open('manuf', 'a', encoding='utf8') as manuf:  # Use 'a' to append data
            for row in reader:
                manuf.write('{}|{}\n'.format(row['Assignment'], row['Organization Name']))
    except urllib.error.HTTPError as e:
        print(f'Error fetching data from {url}: {e}')
    except Exception as e:
        print(f'Error: {e}')