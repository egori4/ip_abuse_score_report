# AbuseIPDB

# About

The script queries two feeds https://www.abuseipdb.com/ and https://www.ipqualityscore.com and creates report with IP list with abuse score and IP information.

# How to run

1. Set the abuseipdb_api_key and ip_quality_score_api_key variables under mykey.py (rename mykey_example.py to mykey.py). 

    * To obtain the API key for abuseipdb, register to https://www.abuseipdb.com/. API key can be found under https://www.abuseipdb.com/account/api (free tier upto 1000 queries per day)

    * To obtain the API key for ipqualityscore, register to https://www.ipqualityscore.com. API key can be found under https://www.ipqualityscore.com/user/settings (free tier limit is 5000 per month as of 2/9/2024)

2. Paste ip list into ip_list.txt
3. Run main.py
4. Read Abuse report under /Report/abuse_report.csv folder

!!! Notes:
- V1.0 does not include IP format validation yet 
    Please make sure:
        - no empty lines exists in the ip_list.txt, 
        - validate proper format of the ip hosts 
            1.1.1.1 is correct
            no subnets - 1.1.1.1/32 or 1.1.1.0 255.255.255.255 is incorrect
            no strings, integers, non valid formated IP lines
- The ip_list.txt should include less than 1000 IP's (IPAbuse free tier allows querying no more than 1000 IP a day)
- The script removes duplicate IP's from the list

# Version management
V1.0 2/12/24

- First release
