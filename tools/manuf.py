#!/usr/bin/env python3

import urllib.request
import csv
import codecs

# Urls to download manufatures CSV
urls = [
	'https://standards.ieee.org/develop/regauth/oui/oui.csv',
	'https://standards.ieee.org/develop/regauth/oui28/mam.csv',
	'https://standards.ieee.org/develop/regauth/oui36/oui36.csv']

with open('manuf','w',encoding='utf8') as manuf:
	for url in urls:
		url_fetcher = urllib.request.urlopen(url)
		reader = csv.DictReader(codecs.iterdecode(url_fetcher, 'utf-8'))
		for row in reader:
			manuf.write('{}|{}\n'.format(row['Assignment'],row['Organization Name']))
