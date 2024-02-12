import requests
import json
import os
import csv
import mykey

###################### Variables ###################
enable_proxy = False
collect_data = True # This flag controls if data needs to be collected from the feeds. False - the script will use the cached data collected from the previous run.
abuse_ip_db = True # Set to true to collect IP information from https://www.abuseipdb.com/
ip_quality_score = True # Set to true to collect IP information from https://www.ipqualityscore.com
create_report = True # This flag controls report generation. False - the script will not create a report
#####################################################


if not os.path.exists('./Raw Data'):
	os.makedirs('./Raw Data')

if not os.path.exists('./Report'):
	os.makedirs('./Report')

raw_data_path = "./Raw Data/"
report_path = "./Report/"


def get_ip_list():
	# Read ip_list.txt, remove duplicate IPs, errors and add to python list ############

	ip_list = [] # holds lines already seen

	with open('ip_list.txt') as f:
		content = f.read().splitlines()
		f.seek(0)

		for ip in content:
			if ip not in ip_list:
				if ip != 'Multiple' and ip !='0.0.0.0':
					ip_list.append(ip)
	return ip_list

def collect_ip_data(ip_list):
	# Collect the data from feeds

	# Create dictionary
	abuse_dict = {}
	
	for ip in ip_list:

		abuse_dict[ip] = {}

		if abuse_ip_db:
			abuse_ip_db_response = abuse_ip_db_call(ip)
			abuse_dict[ip]['AbuseIPDB Src IP details'] = abuse_ip_db_response['data']

		if ip_quality_score:	
			ip_quality_score_response = ip_quality_score_call(ip)
			abuse_dict[ip]['IPQualityScore Src IP details'] = ip_quality_score_response

	with open(raw_data_path + 'abuse_dic_raw.json', 'w') as outfile:
		json.dump(abuse_dict,outfile)


def abuse_ip_db_call(ipAddress):
	# Call to https://api.abuseipdb.com
	url = 'https://api.abuseipdb.com/api/v2/check'

	querystring = {
		'ipAddress': ipAddress,
		'maxAgeInDays': '90'
	}

	headers = {
		'Accept': 'application/json',
		'Key': mykey.abuseipdb_api_key
	}
	
	proxy = {
		'http': 'http://your_proxy_url',
		'https': 'https://your_proxy_url'
	}

	if enable_proxy:
		response = requests.request(method='GET', url=url, headers=headers, params=querystring, proxies=proxy)

	else:
		response = requests.request(method='GET', url=url, headers=headers, params=querystring)

	# Formatted output
	decodedResponse = json.loads(response.text)
	# print(json.dumps(decodedResponse, sort_keys=True, indent=4))

	return decodedResponse


def ip_quality_score_call(ip):
	# Call to https://ipqualityscore.com
	url = f'https://ipqualityscore.com/api/json/ip/{mykey.ip_quality_score_api_key}/{ip}'

	# Send the API request
	response = requests.get(url)

	# Check if the request was successful
	if response.status_code == 200:
		# Parse the JSON response
		data = response.json()
		return(data)
		
	else:
		print("Error:", response.status_code)
		return("Error:", response.status_code)

def parse_data_create_report():
	# Parse collected data

	with open(raw_data_path + 'abuse_dic_raw.json', 'r') as f:
		abuse_dic_raw_str = f.read()
		abuse_dic_raw_dict= json.loads(abuse_dic_raw_str)

	# Create report csv and headers
	with open(report_path + 'abuse_report.csv', mode='w', newline="") as abuseipdb_report:
		bdos_writer = csv.writer(abuseipdb_report, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
		bdos_writer.writerow(['IP Address' , 'Confidence of Abuse(AbuseIPDB)' , 'Fraud Score(IPQualityScore)','Proxy Status(IPQualityScore)','VPN Status(IPQualityScore)','TOR Status(IPQualityScore)','Bot Activity(IPQualityScore)','Recent Abuse(IPQualityScore)', 'Country(AbuseIPDB)' , 'Usage Type(AbuseIPDB)' , 'ISP(AbuseIPDB)' , 'Domain Name(AbuseIPDB)', 'Hosnames(AbuseIPDB)', 'Total Reports(AbuseIPDB)', 'Distinct Users(AbuseIPDB)' , 'Last reported(AbuseIPDB)'])


	for ip, ip_details in abuse_dic_raw_dict.items():
		abuse_confidence_score_abuse_ipdb = 'N/A'
		fraud_score_ipquality_score = 'N/A'
		proxy_ipquality_score = 'N/A'
		vpn_ipquality_score = 'N/A'
		tor_ipquality_score = 'N/A'
		bot_ipquality_score = 'N/A'
		recent_abuse_ipquality_score = 'N/A'
		country_abuse_ipdb = 'N/A'
		usage_type_abuse_ipdb = 'N/A'
		isp_abuse_ipdb = 'N/A'
		domain_abuse_ipdb = 'N/A'
		hostnames_abuse_ipdb = 'N/A'
		total_reports_abuse_ipdb = 'N/A'
		distinct_users_abuse_ipdb = 'N/A'
		last_reported_abuse_ipdb = 'N/A'

		if abuse_ip_db:
			abuse_ipdb_details = ip_details.get('AbuseIPDB Src IP details')
			if abuse_ipdb_details:
				abuse_confidence_score_abuse_ipdb = abuse_ipdb_details.get('abuseConfidenceScore')
				country_abuse_ipdb = abuse_ipdb_details.get('countryCode')
				usage_type_abuse_ipdb = abuse_ipdb_details.get('usageType')
				isp_abuse_ipdb = abuse_ipdb_details.get('isp')
				domain_abuse_ipdb = abuse_ipdb_details.get('domain')
				hostnames_abuse_ipdb = (', '.join(abuse_ipdb_details.get('hostnames')))
				total_reports_abuse_ipdb = abuse_ipdb_details.get('totalReports')
				distinct_users_abuse_ipdb = abuse_ipdb_details.get('numDistinctUsers')
				last_reported_abuse_ipdb = abuse_ipdb_details.get('lastReportedAt')

		if ip_quality_score:
			ip_quality_score_details = ip_details.get('IPQualityScore Src IP details')
			if ip_quality_score_details:
				fraud_score_ipquality_score = ip_quality_score_details.get('fraud_score')
				proxy_ipquality_score = ip_quality_score_details.get('proxy')
				vpn_ipquality_score = ip_quality_score_details.get('vpn')
				tor_ipquality_score = ip_quality_score_details.get('tor')
				bot_ipquality_score = ip_quality_score_details.get('bot_status')
				recent_abuse_ipquality_score = ip_quality_score_details.get('recent_abuse')

		with open(report_path + 'abuse_report.csv', mode='a', newline="") as abuseipdb_report:
			bdos_writer = csv.writer(abuseipdb_report, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
			bdos_writer.writerow([ip , abuse_confidence_score_abuse_ipdb , fraud_score_ipquality_score, proxy_ipquality_score, vpn_ipquality_score, tor_ipquality_score,bot_ipquality_score,recent_abuse_ipquality_score, country_abuse_ipdb , usage_type_abuse_ipdb , isp_abuse_ipdb , domain_abuse_ipdb, hostnames_abuse_ipdb, total_reports_abuse_ipdb, distinct_users_abuse_ipdb , last_reported_abuse_ipdb])

def run():
	
	# 1. Read the list of IP's from ip_list.txt
	ip_list = get_ip_list()

	# 2. Collect the data
	if collect_data:
		collect_ip_data(ip_list)

	# 3. parse the collected data
	if create_report:
		parse_data_create_report()

run()