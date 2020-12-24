from mega import Mega

def download_file(m, url, filepath):
    m.download_url(url, filepath)

def init():
    mega = Mega()
    m = mega.login()
    return m