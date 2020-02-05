import argparse
import csv
import json
import os
import pathlib
import re
import time
import urllib.parse

import requests

class Hibp:
    
    def __init__(self, email, api_key=None):
        self.email = self.__url_encode(email)
        self.api_key = api_key
        self.params = { "truncateResponse": "false" }
        self.header = {}
        
    def __set_header(self):
        if not self.api_key:
            print("[!] Failed to execute command, please define an api key")
            return False
        else:
            self.header = {
                "hibp-api-key": self.api_key
            }
            
            return True
            
    def __url_encode(self, string):
        return urllib.parse.quote_plus(string)
        
    def __build_request(self, type, attempt=1):
        if not self.__set_header():
            return False
            
        url = f"https://haveibeenpwned.com/api/v3/{type}/{self.email}"
        response = requests.get(url, headers=self.header, params=self.params)
        
        if response.status_code == 404:
            return None
        elif response.status_code == 429:
            try:
                time.sleep(int(re.findall("Rate limit is exceeded. Try again in (.*?) seconds.", json.loads(response.text).get("message"))[0]))
            except:
                if attempt > 6:
                    attempt = 7
                time.sleep(5 * attempt)
            return self.__build_request(type, attempt + 1)
        elif response.status_code != 200:
            print(f"[!] Error, status code: {response.status_code}")
            print(response.text)
            input()
            return False
        elif response.text:
            return json.loads(response.text)
        else:
            return None
            
    def get_breaches(self):
        data = self.__build_request("breachedaccount")
        if data:
            return data
        else:
            return []
            
    def get_pasteaccount(self):
        data = self.__build_request("pasteaccount")
        if data:
            return data
        else:
            return []

def find_account_information(email_accounts):
    ba_header = ["Email", "AddedDate", "BreachDate", "DataClasses", "Description", "Domain", 
                 "ModifiedDate", "Name", "PwnCount", "Source", "Title", "Date", "Id", "EmailCount",
                 "IsFabricated", "IsSpamList", "IsRetired", "LogoPath", "IsSensitive", "IsVerified"]
    pa_header = ["Email", "Date", "EmailCount", "Id", "Source", "Title"]
    
    timestamp = time.strftime("%Y%m%d-%H%M%S_")
    ba_csv = os.path.join(args.outfolder, f"{timestamp}breached_accounts.csv")
    pa_csv = os.path.join(args.outfolder, f"{timestamp}pasted_accounts.csv")
    
    with open(ba_csv, "w", newline='', encoding='utf-8') as ba, open(pa_csv, "w", newline='', encoding='utf-8') as pa:
        bw = csv.DictWriter(ba, quoting=csv.QUOTE_ALL, fieldnames=ba_header)
        pw = csv.DictWriter(pa, quoting=csv.QUOTE_ALL, fieldnames=pa_header)
        bw.writeheader()
        pw.writeheader()
        
    print("[*] Parsing the following accounts:")
    for email_account in email_accounts:
        print(f"\t{email_account}")
        time.sleep(1.6)
        hibp = Hibp(email_account, args.token)
        data = hibp.get_breaches()
        if data:
            with open(ba_csv, "a", newline='', encoding='utf-8') as ba:
                bw = csv.DictWriter(ba, quoting=csv.QUOTE_ALL, fieldnames=ba_header)
                for row in data:
                    row["Email"] = email_account
                    bw.writerow(row)
        
        data = hibp.get_pasteaccount()
        if data:
            with open(pa_csv, "a", newline='', encoding='utf-8') as pa:
                pw = csv.DictWriter(pa, quoting=csv.QUOTE_ALL, fieldnames=pa_header)
                for row in data:
                    row["Email"] = email_account
                    pw.writerow(row)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Tool used to find breach information about accounts")
    parser.add_argument("-u", "--user_list", type=str, help="filepath with email addresses")
    parser.add_argument("-U", "--user", type=str, help="email address for a single check")
    parser.add_argument("-o", "--outfolder", type=str, help="folder to store findings")
    parser.add_argument("-t", "--token", type=str, help="api token to use for hibp")
    
    args = parser.parse_args()
    
    if (args.user_list and args.user) or (not args.user_list and not args.user):
        print("[!] You can either submit a user list file or a user")
        exit()
        
    if not args.outfolder:
        args.outfolder = os.path.join(os.getcwd(), "hipd")
        print(f"[!] No folder path was supplied, using {args.outfolder}")
     
    try:
        pathlib.Path(args.outfolder).mkdir(parents=True, exist_ok=True)
    except:
        print(f"[!] Unable to create {args.outfolder}, please manually create it and then rerun app")
        exit()
    
    
    if args.user:
        find_account_information([args.user])
    elif args.user_list:
        if os.path.isfile(args.user_list):
            users = [u.strip().lower() for u in open(args.user_list).readlines()]
            user_list = list(set(users))
            user_list.sort()
            find_account_information(user_list)
        else:
            print(f"[!] Unable to find user file {args.user_list}")
            exit()
        
    print("[*] Done")

