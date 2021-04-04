#!/usr/bin/python3
# coding: utf-8
# CTFe7ch v1.1
# By Ting-Wei (Leo) Wang - twitter.com/l3ouu4n9

import time
import re
import os
import json

# external modules
import requests
import importlib
from bs4 import BeautifulSoup
from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter
from tqdm import tqdm

# My own module
from gdrive import GDrive


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
    def __init__(self, username, password, url, verbose, category_list, plugin):
        self.user           = username
        self.password       = password
        self.url            = url
        self.verbose        = verbose
        self.category_list  = category_list
        self.plugin         = plugin
        self.user_id        = ""
        self.nonce          = ""

    def get_nonce(self):
        content = session.get(self.url.format("login")).text
        
        soup = BeautifulSoup(content, 'html.parser')
        self.nonce = soup.find_all("input", attrs={"name":"nonce", "type":"hidden"})[0].get("value")
        

    def login(self):

        login_data = {
            "name" : self.user,
            "password" : self.password,
            "nonce" : self.nonce,
            "_submit" : "Submit",
        }
        login = session.post(self.url.format("login"), data=login_data).text

        if "incorrect" in login:
            print("Wrong credentials.")
            exit(1)
        
        try:
            self.user_id = re.findall("'userId': (.*),", login)[0]
            print("\n[*] Logged in Successfully as {}.\n".format(self.user))
        except:
            print("\n[*] Logged in Successfully.\n")
 
    def get_challenges(self):
        challs_data = json.loads(session.get(self.url.format("api/v1/challenges")).text)['data']
        
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

        response = session.get(self.url.format("api/v1/challenges/%d" % id)).text.encode("ascii", "ignore").decode()
        files    = json.loads(response)['data']['files']
        
        category  = json.loads(response)['data']['category'].encode("ascii", "ignore").decode().rstrip()
        challname = json.loads(response)['data']['name'].encode("ascii", "ignore").decode().rstrip()

        if challname[0] == ' ':
            challname = challname[1:]
        challname = challname.replace(' ', '_').replace('/', '_')

        if category[0] == ' ':
            category = category[1:]
        category = category.replace(' ', '_').replace('/', '_')
        
        filepath  = "{}/{}/{}/".format(directory, category, challname)
        
        description = json.loads(response)['data']['description'].encode("ascii", "ignore").decode()

        print("[*] Downloading Challenge {}.".format(challname))

        content = "".join([
            "\n# {}".format(challname),
            "\n## Description:\n{}\n\n".format(description)
        ])

        if self.verbose:
            tags = list(tag.encode("ascii", "ignore").decode() for tag in json.loads(response)['data']['tags'])
            value  = json.loads(response)['data']['value']
            solves = json.loads(response)['data']['solves']

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
        
        
        original_response = response
        for path in files:
            url = self.url.format(path)
            filename = re.findall('/(.*)?token', path)[0].split('/')[-1][:-1]
            target = filepath + filename
            try:
                print(" |  Downloading {}".format(filename))
                response = session.get(url, stream=True)
                with tqdm.wrapattr(open(target, "wb"), "write",
                        miniters=1, total=int(response.headers.get('content-length', 0))) as fout:
                    for chunk in response.iter_content(chunk_size=4096):
                        fout.write(chunk)

            except IOError:
                print("[!] Failed to download the challenge {}.".format(challname))
                time.sleep(1)
                continue
            except KeyboardInterrupt:
                print("\n\n[!] Exiting program.")
                exit(1)

        # Check google drive link and google cloud storage exists
        soup = BeautifulSoup(original_response, 'html.parser')
        a_tags = soup.find_all('a')
        drive_urls = []
        storage_urls = []
        for tag in a_tags:
            try:
                a = tag.get('href')
                if 'drive.google.com' in a:
                    drive_urls.append(a[2:-2])
                elif 'storage.googleapis' in a:
                    storage_urls.append(a[2:-2])
            except:
                pass

        # Get unique
        drive_urls = list(set(drive_urls))
        storage_urls = list(set(storage_urls))

        # Download google cloud storage files
        for url in storage_urls:
            filename = url.split('/')[-1]
            target = filepath + filename
            try:
                print(" |  Downloading {}".format(filename))
                response = session.get(url, stream=True)
                with tqdm.wrapattr(open(target, "wb"), "write",
                        miniters=1, total=int(response.headers.get('content-length', 0))) as fout:
                    for chunk in response.iter_content(chunk_size=4096):
                        fout.write(chunk)

            except IOError:
                print("[!] Failed to download the challenge {}.".format(challname))
                time.sleep(1)
                continue
            except KeyboardInterrupt:
                print("\n\n[!] Exiting program.")
                exit(1)
        
        # Download google drive files
        for url in drive_urls:
            file_id = re.findall('/file/d/(.*?)/', url)[0]
            filename = filepath + GDrive.get_file_name(url)
            print(" |  Downloading Goolge Drive File from {}".format(challname))
            try:
                GDrive.download_file(file_id, filename)

            except IOError:
                print("[!] Failed to download the challenge {}.".format(challname))
                time.sleep(1)
                continue
            except KeyboardInterrupt:
                print("\n\n[!] Exiting program.")
                exit(1)

        
        
        # MEGA
        if self.plugin == 'mega':
            urls = list(url[1:-1] for url in re.findall('\(https://mega.nz/file/.*?\)', original_response))
            if urls:
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

class rCTF:
    def __init__(self, token, url, verbose, category_list, plugin):
        self.token          = token
        self.url            = url
        self.verbose        = verbose
        self.category_list  = category_list
        self.plugin         = plugin
        self.auth_token     = ""


    def login(self):

        login_data = {
            "teamToken": self.token
        }
        
        headers = {
            "Content-Type": "application/json"
        }
        login = session.post(self.url.format("api/v1/auth/login"), json=login_data, headers=headers).text
        
        if "invalid" in login:
            print("Wrong login token.")
            exit(1)
        else:
            print("\n[*] Logged in Successfully.\n")
            self.auth_token = json.loads(login)["data"]["authToken"]

    def get_challenges(self):
        headers = {
            "Authorization": "Bearer " + self.auth_token
        }
        challs_data = json.loads(session.get(self.url.format("api/v1/challs"), headers=headers).text)['data']
        categories = list(set([chall['category'].encode('ascii', 'ignore').decode() for chall in challs_data]))
        
        dict_data = {}
        for category in categories:
            temp_data = []
            for data in challs_data:
                if data['category'] == category:
                    temp_data.append([data['name'], data['description'], data['points'], data['solves']])
            dict_data[category.encode('ascii', 'ignore').decode()] = temp_data
        return categories, dict_data

    def download_challenge(self, data, category, directory):
        files = re.findall('\[Chal.*\]\((.*)\)', data[1])
        challname = data[0]
        if challname[0] == ' ':
            challname = challname[1:]
        challname = challname.replace(' ', '_').replace('/', '_')

        filepath  = "{}/{}/{}/".format(directory, category, challname)

        description = data[1].encode("ascii", "ignore").decode().replace('```','')

        print("[*] Downloading Challenge {}.".format(challname))

        content = "".join([
            "\n# {}".format(challname),
            "\n## Description:\n{}\n\n".format(description)
        ])
        
        
        if self.verbose:
            value = data[2]
            solves = data[3]

            content = "".join([
                "\n# {}".format(challname),
                "\n- Value: {} points".format(value),
                "\n- Solves: {} teams".format(solves),
                "\n## Description:\n{}\n\n".format(description)
            ])

        if not os.path.exists(filepath):
            os.makedirs(filepath)

        with open(filepath + "README.md", "w") as f:
            f.write(content)
            f.close()

        
        
        for url in files:
            if 'drive.google.com' not in url:
                filename = url.split('/')[-1]
                target = filepath + filename
                try:
                    print(" |  Downloading {}".format(filename))
                    response = session.get(url, stream=True)
                    with tqdm.wrapattr(open(target, "wb"), "write",
                            miniters=1, total=int(response.headers.get('content-length', 0))) as fout:
                        for chunk in response.iter_content(chunk_size=4096):
                            fout.write(chunk)

                except IOError:
                    print("[!] Failed to download the challenge {}.".format(challname))
                    time.sleep(1)
                    continue
                except KeyboardInterrupt:
                    print("\n\n[!] Exiting program.")
                    exit(1)
            elif 'drive.google.com' in url:
                file_id = re.findall('/file/d/(.*?)/', url)[0]
                filename = filepath + GDrive.get_file_name(url)
                print(" |  Downloading Goolge Drive File from {}".format(challname))
                try:
                    GDrive.download_file(file_id, filename)

                except IOError:
                    print("[!] Failed to download the challenge {}.".format(challname))
                    time.sleep(1)
                    continue
                except KeyboardInterrupt:
                    print("\n\n[!] Exiting program.")
                    exit(1)
        
        if self.plugin == 'mega':
            for url in files:
                if 'https://mega.nz/file/' in url:
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
            datas = challs_data[category]
            for data in datas:
                self.download_challenge(data, category, directory)


class CTFx:
    def __init__(self, username, password, url, verbose, category_list, plugin):
        self.email          = username
        self.password       = password
        self.url            = url
        self.verbose        = verbose
        self.category_list  = category_list
        self.plugin         = plugin
        self.email_name     = ""
        self.password_name  = ""

    def get_email_password_name(self):
        content = session.get(self.url.format("home")).text
        
        soup = BeautifulSoup(content, 'html.parser')
        self.email_name = soup.find_all("input", attrs={"type":"email"})[0].get("name")
        self.password_name = soup.find_all("input", attrs={"type":"password"})[0].get("name")

        
    def login(self):

        login_data = {
            self.email_name : self.email,
            self.password_name : self.password,
            "action" : "login",
            "redirect" : "/actions/login",
        }
        login = session.post(self.url.format("actions/login"), data=login_data).text

        if "failed" in login:
            print("Wrong credentials.")
            exit(1)
        
        try:
            print("\n[*] Logged in Successfully as {}.\n".format(self.user))
        except:
            print("\n[*] Logged in Successfully.\n")

 
    def get_categories(self):
        
        content = session.get(self.url.format("challenges")).text
        soup = BeautifulSoup(content, 'html.parser')
        content = soup.find(id='categories-menu')
        a_tag = content.find_all("a")
        categories = []
        for tag in a_tag:
            categories.append(tag.string.encode('ascii', 'ignore').decode())
        return categories

    def get_challenges(self, category):
        param = {'category': category}
        content = session.get(self.url.format("challenges"), params=param).text
        soup = BeautifulSoup(content, 'html.parser')
        cards = soup.find_all("div", class_="ctfx-card")
        
        return cards
        
        

    def download_challenge_by_card(self, card, directory, category):
        
        tmps     = card.find("div", class_="ctfx-card-body").find_all("div", class_="challenge-file")
        files = []
        for tmp in tmps:
            files.append(tmp.find("a"))
        
        category  = category
        challname = card.find("div", class_="ctfx-card-head").find("a").string.encode("ascii", "ignore").decode().rstrip()
        
        if challname[0] == ' ':
            challname = challname[1:]
        challname = challname.replace(' ', '_').replace('/', '_')

        if category[0] == ' ':
            category = category[1:]
        category = category.replace(' ', '_').replace('/', '_')
        
        filepath  = "{}/{}/{}/".format(directory, category, challname)
        
        description = str(card.find("div", class_="ctfx-card-body").find("div", class_="challenge-description")).encode("ascii", "ignore").decode()

        print("[*] Downloading Challenge {}.".format(challname))

        content = "".join([
            "\n# {}".format(challname),
            "\n## Description:\n{}\n\n".format(description)
        ])
        
        if self.verbose:
            
            value  = card.find("div", class_="ctfx-card-head").find("small").string
            
            content = "".join([
                "\n# {}".format(challname),
                "\n- Value: {}".format(value),
                "\n## Description:\n{}\n\n".format(description)
            ])
        
        if not os.path.exists(filepath):
            os.makedirs(filepath)

        with open(filepath + "README.md", "w") as f:
            f.write(content)
            f.close()
        
        
        for f in files:
            url = self.url.format(f.get('href'))
            filename = f.string
            target = filepath + filename
            
            try:
                print(" |  Downloading {}".format(filename))
                response = session.get(url, stream=True)
                with tqdm.wrapattr(open(target, "wb"), "write",
                        miniters=1, total=int(response.headers.get('content-length', 0))) as fout:
                    for chunk in response.iter_content(chunk_size=4096):
                        fout.write(chunk)

            except IOError:
                print("[!] Failed to download the challenge {}.".format(challname))
                time.sleep(1)
                continue
            except KeyboardInterrupt:
                print("\n\n[!] Exiting program.")
                exit(1)

        drive_urls = []
        storage_urls = []

        if 'drive.google.com' in description:
            drive_urls = re.findall('(http.*?drive.google.com.*?)<br', description)

        elif 'storage.googleapis' in description:
            storage_urls = re.findall('(http.*?storage.googleapis.*?)<br', description)
            
        

        # Download google cloud storage files
        for url in storage_urls:
            filename = url.split('/')[-1]
            target = filepath + filename
            try:
                print(" |  Downloading {}".format(filename))
                response = session.get(url, stream=True)
                with tqdm.wrapattr(open(target, "wb"), "write",
                        miniters=1, total=int(response.headers.get('content-length', 0))) as fout:
                    for chunk in response.iter_content(chunk_size=4096):
                        fout.write(chunk)

            except IOError:
                print("[!] Failed to download the challenge {}.".format(challname))
                time.sleep(1)
                continue
            except KeyboardInterrupt:
                print("\n\n[!] Exiting program.")
                exit(1)
        
        # Download google drive files
        for url in drive_urls:
            file_id = re.findall('/file/d/(.*?)/', url)[0]
            filename = filepath + GDrive.get_file_name(url)
            print(" |  Downloading Goolge Drive File from {}".format(challname))
            try:
                GDrive.download_file(file_id, filename)

            except IOError:
                print("[!] Failed to download the challenge {}.".format(challname))
                time.sleep(1)
                continue
            except KeyboardInterrupt:
                print("\n\n[!] Exiting program.")
                exit(1)

        
        
        # MEGA
        if self.plugin == 'mega':
            mega_urls = []
            if '/mega.nz/file/' in description:
                mega_urls = re.findall('(http.*?mega.nz/file.*?)<br', description)
            if mega_urls:
                mega = importlib.import_module('mega-plugin')
                m = mega.init()
                for url in mega_urls:
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

        

    def start_download(self, directory):
        categories = self.get_categories()
        
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
            card_list = self.get_challenges(category)
            
            for card in card_list:
                self.download_challenge_by_card(card, directory, category)
            
        


if __name__ == "__main__":

    args = ArgumentParser(
        prog="python3 ctfe7ch.py",
        description="CTFe7ch is a python tool designed to download Capture The Flag (CTF) challenges and files.",
        formatter_class=ArgumentDefaultsHelpFormatter
    )
    args.add_argument('-u', '--user', metavar='USERNAME', type=str, help='Username or email of your login credentials')
    args.add_argument('-p', '--password', metavar='PASSWORD', type=str, help='Password of your login credentials')
    args.add_argument('-t', '--token', metavar='TOKEN', type=str, help='Token of your login credentials')
    args.add_argument('url', metavar='BASE_URL', type=str, help='Base URL of the CTF challenge')
    args.add_argument('-o', '--output', metavar='OUTPUT_DIRECTORY', type=str, help='Save the files to directory')
    args.add_argument('-v', '--verbose', help='Increase challenge verbosity, includes tags, solves, and points', action='store_true')
    args.add_argument('-c', '--category', help='Specify categories to fetch, split with \',\' e.g. web,pwn,"vulncon 2020"', default='all')
    args.add_argument('--platform', metavar='PLATFORM', type=str, help='Specify the platform hosting CTF. e.g. ctfd, rctf, or ctfx.', choices=['ctfd', 'rctf', 'ctfx'], default='ctfd')
    args.add_argument('--plugin', metavar='PLUGIN', type=str, help='Specify the plugin to use. For now, we only provide mega plugin', choices=['mega'])
    args = args.parse_args()

    banner()

    if args.platform == 'ctfd':
        if args.user != None and args.password != None and args.url != None and args.output != None:
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
                args.plugin
            )

            ctfd.get_nonce()
            ctfd.login()
            ctfd.start_download(args.output)
            
        else:
            print('Arguments required, try \'-h\' for help.')
    elif args.platform == 'rctf':
        if args.token != None and args.url != None and args.output != None:
            session  = requests.Session()
            base_url = args.url
            
            if not base_url.endswith('/'):
                base_url += '/{}'
            else:
                base_url += '{}'
            
            category_list = [c.lower() for c in list(args.category.split(','))]
            
            rctf = rCTF(
                args.token,
                base_url,
                args.verbose,
                category_list,
                args.plugin
            )

            rctf.login()
            rctf.start_download(args.output)
            
        else:
            print('Arguments required, try \'-h\' for help.')
    
    elif args.platform == 'ctfx':
        if args.user != None and args.password != None and args.url != None and args.output != None:
            session  = requests.Session()
            base_url = args.url
            
            if not base_url.endswith('/'):
                base_url += '/{}'
            else:
                base_url += '{}'
            
            category_list = [c.lower() for c in list(args.category.split(','))]
            
            ctfx = CTFx(
                args.user,
                args.password,
                base_url,
                args.verbose,
                category_list,
                args.plugin
            )

            ctfx.get_email_password_name()
            ctfx.login()
            ctfx.start_download(args.output)
            
        else:
            print('Arguments required, try \'-h\' for help.')