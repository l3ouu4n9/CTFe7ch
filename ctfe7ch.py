#!/usr/bin/python3
# coding: utf-8
# CTFe7ch v1.0
# By Ting-Wei (Leo) Wang - twitter.com/l3ouu4n9

import time
import re
import os
from json import loads

# external modules
import requests
import importlib
from bs4 import BeautifulSoup
from argparse import ArgumentParser


def banner():
    print("""
              ____ _____ _____   _____    _     
             / ___|_   _|  ___|_|___  |__| |__  
            | |     | | | |_ / _ \ / / __| '_ \ 
            | |___  | | |  _|  __// / (__| | | |
             \____| |_| |_|  \___/_/ \___|_| |_|

                 # Coded By Leo Wang - @l3ouu4n9
    """)


class CTFd:
    def __init__(self, username, password, url, verbose, category_list, download_type):
        self.user           = username
        self.password       = password
        self.url            = url
        self.verbose        = verbose
        self.category_list  = category_list
        self.download_type  = download_type
        self.user_id        = ""
        self.nonce          = ""

    def get_nonce(self):
        content = session.get(self.url.format("login")).text
        self.nonce = re.findall('<input id="nonce" name="nonce" type="hidden" value="(.*)">', content)[0]

    def login(self):

        login_data = {
            "name" : self.user,
            "password" : self.password,
            "nonce" : self.nonce,
            "_submit" : "Submit",
        }
        login = session.post(self.url.format("login"), data=login_data).text
    
        self.user_id = re.findall("'userId': (.*),", login)[0]
        if "incorrect" in login:
            print("Wrong credentials.")
            exit(1)
        print("\n[*] Logged in Successfully as {}.\n".format(self.user))
 
    def get_challenges(self):
        challs_data = loads(session.get(self.url.format("/api/v1/challenges")).text)['data']
        categories = list(set([chall['category'].encode('ascii', 'ignore').decode() for chall in challs_data]))
        
        dict_data = {}
        for category in categories:
            temp_data = []
            for data in challs_data:
                if data['category'] == category:
                    temp_data.append([data['id'], data['name'].encode('ascii', 'ignore'), data['value']])
            dict_data[category.encode('ascii', 'ignore').decode()] = temp_data
        return categories, dict_data
        

    def download_challenge_by_id(self, id, directory):

        response = session.get(self.url.format("api/v1/challenges/%d" % id)).text
        files    = loads(response)['data']['files']
        
        category  = loads(response)['data']['category'].encode("ascii", "ignore").decode().replace(' ', '_')
        challname = loads(response)['data']['name'].encode("ascii", "ignore").decode().replace(' ', '_')
        filepath  = "{}/{}/{}/".format(directory, category, challname)
        
        description = loads(response)['data']['description'].encode("ascii", "ignore").decode()

        print("[*] Downloading Challenge {}.".format(challname))

        content = "".join([
            "\n# {}".format(challname),
            "\n## Description:\n{}\n\n".format(description)
        ])

        if self.verbose:
            tags = list(tag.encode("ascii", "ignore").decode() for tag in loads(response)['data']['tags'])
            value  = loads(response)['data']['value']
            solves = loads(response)['data']['solves']

            content = "".join([
                "\n# {}".format(challname),
                "\n- Tags: {}".format(tags),
                "\n- Value: {} points".format(value),
                "\n- Solves: {} teams".format(solves),
                "\n## Description:\n{}\n\n".format(description)
            ])
        
        if not os.path.exists(filepath):
            os.makedirs(filepath)

        with open(filepath + "README.md", "w") as f:
            f.write(content)
            f.close()
        
        if self.download_type == 'ctfd':
            for path in files:
                url = self.url.format(path)
                filename = re.findall('/(.*)?token', path)[0].split('/')[-1][:-1]
                target = filepath + filename
                try:
                    print(" |  Downloading {}".format(filename))
                    data = session.get(url).content
                    with open(target, 'wb') as f:
                        f.write(data)
                        f.close()

                except IOError:
                    print("[!] Failed to download the challenge {}.".format(challname))
                    time.sleep(1)
                    continue
                except KeyboardInterrupt:
                    print("\n\n[!] Exiting program.")
                    exit(1)
        
        elif self.download_type == 'mega':
            urls = list(url[1:-1] for url in re.findall('\(https://mega.nz/file/.*?\)', response))
            mega = importlib.import_module('mega-plugin')
            m = mega.init()
            for url in urls:
                print(" |  Downloading Mega File from {}".format(challname))
                try:
                    mega.download_file(m, url, filepath)

                except IOError:
                    print("[!] Failed to download the challenge {}.".format(challname))
                    time.sleep(1)
                    continue
                except KeyboardInterrupt:
                    print("\n\n[!] Exiting program.")
                    exit(1)
        else:
            print('[!] Failed to download the Challenge {}.')
        
        
    def start_download(self, directory):
        categories, challs_data = self.get_challenges()

        if 'all' not in self.category_list:
            tmp_categories = []
            for category in categories:
                if category.lower() in self.category_list:
                    tmp_categories.append(category)
            
            if len(tmp_categories) != len(self.category_list):
                tmp_categories = [c.lower() for c in tmp_categories]
                print("[!] Categories {} not found.".format(set(self.category_list).difference(tmp_categories)))
                print("\n[!] Exiting program.")
                exit(1)

            categories = tmp_categories
        

        for category in categories:
            print("----------------------------\n[=] {} CHALLENGE\n----------------------------".format(category.upper()))
            data = challs_data[category]
            for i in range(len(data)):
                id = data[i][0]
                self.download_challenge_by_id(id, directory)
    

if __name__ == "__main__":

    args = ArgumentParser()
    args.add_argument('-u', '--user', metavar='USERNAME', type=str, help='Username or email of your login credentials')
    args.add_argument('-p', '--password', metavar='PASSWORD', type=str, help='Password of your login credentials')
    args.add_argument('url', metavar='BASE_URL', type=str, help='Base URL of the CTF challenge')
    args.add_argument('-o', '--output', metavar='OUTPUT_DIRECTORY', type=str, help='Save the files to directory')
    args.add_argument('-v', '--verbose', help='Increase challenge verbosity, includes tags, solves, and points', action='store_true')
    args.add_argument('-c', '--category', help='Specify categories to fetch, split with \',\' e.g. web,pwn,"vulncon 2020"', default='all')
    args.add_argument('--download-type', metavar='DOWNLOAD_TYPE', type=str, help='Specify where the challenge files come from, e.g. ctfd, mega', default='ctfd')
    args = args.parse_args()

    banner()
    
    if args.user != None and args.password != None and args.url != None and args.output != None:
        if args.download_type == 'ctfd' or args.download_type == 'mega':
            
            session  = requests.Session()
            base_url = args.url
            
            if not base_url.endswith('/'):
                base_url += '/{}'
            else:
                base_url += '{}'
            
            category_list = [c.lower() for c in list(args.category.split(','))]
            
            ctfd = CTFd(
                args.user,
                args.password,
                base_url,
                args.verbose,
                category_list,
                args.download_type
            )

            ctfd.get_nonce()
            ctfd.login()
            ctfd.start_download(args.output)
        else:
            print('Download Type not supported, Only ctfd or mega')
    else:
        print('Arguments required, try \'-h\' for help.')