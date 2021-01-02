#!/usr/bin/python3
# coding: utf-8
# Google Drive Plugin
# By Ting-Wei (Leo) Wang - twitter.com/l3ouu4n9

import requests
import re
from tqdm import tqdm

class GDrive:
    def __init__():
        pass
    def download_file(id, destination):
        URL = "https://docs.google.com/uc?export=download"

        session = requests.Session()

        response = session.get(URL, params = { 'id' : id }, stream = True)
        token = GDrive.get_confirm_token(response)
        if token:
            params = { 'id' : id, 'confirm' : token }
            response = session.get(URL, params = params, stream = True)
        with tqdm.wrapattr(open(destination, "wb"), "write", miniters=1,total=int(response.headers.get('content-length', 0))) as f:
            for chunk in response.iter_content(chunk_size=4096):
                if chunk: # filter out keep-alive new chunks
                    f.write(chunk)
        

    def get_confirm_token(response):
        for key, value in response.cookies.items():
            if key.startswith('download_warning'):
                return value

        return None


    def get_file_name(url):
        r = requests.get(url)
        text = r.text.encode('ascii', 'ignore').decode()
        filename = re.findall('<title>(.*?)</title>', text)[0].split(' - Google')[0]
        return filename