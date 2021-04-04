# CTFe7ch

CTFe7ch is a python tool designed to download Capture The Flag (CTF) challenges and files. It helps CTFers to gather resources from the competition. Files provided from CTFd framework, rCTF framework, CTFx framework, MEGA cloud storage, Google Drive, and Google Cloud Storage are all available. Now it supports CTFs hosted on [CTFd](https://github.com/CTFd/CTFd), [rCTF](https://github.com/redpwn/rctf), and [CTFx](https://gitlab.com/Milkdrop/ctfx). It may support other frameworks in the future.

## Screenshots

![CTFe7ch](https://github.com/l3ouu4n9/CTFe7ch/blob/main/images/CTFe7ch_1.png "CTFe7ch in action")
![CTFe7ch](https://github.com/l3ouu4n9/CTFe7ch/blob/main/images/CTFe7ch_2.png "CTFe7ch in action")

## Installation

```
git clone https://github.com/l3ouu4n9/CTFe7ch.git
```

## Supported Python Version:
CTFe7ch currently supports **Python 3** only.

## Dependencies:
CTFe7ch depends on the `requests`, `bs4`, `argparse`, `importlib`, and `tqdm` python modules.

These dependencies can be installed using the requirements file:

- Installation on Linux
```
sudo python3 -m pip install -r requirements.txt
```

If the CTF files are from [MEGA]("https://mega.nz"), the MEGA API python module is required.
#### MEGA module
- Installation on Linux:
```
sudo python3 -m pip install mega.py
```

## Usage

Try -h to show the menu list.

Short Form    | Long Form       | Description
------------- | -------------   |-------------
-u            | --username      | Username or email of your login credentials
-p            | --password      | Password of your login credentials
-t            | --token         | Token of your login credentials
-o            | --output        | Save the files to the directory
-v            | --verbose       | Increase challenge description verbosity, includes tags, solves, and points
-c            | --category      | Specify categories to fetch, split with "`,`" e.g. web,pwn,"vulncon 2020". Default: all
|             | --platform      | Specify the platform hosting CTF. e.g. ctfd, rctf, or ctfx. Default: ctfd
|             | --plugin        | Specify the plugin to use. For now, we only provide mega plugin
-h            | --help          | Show the help message and exit

### Examples

* To list all the basic options and switches use -h switch:

```python3 ctfe7ch.py -h```

* To download CTF challenges:

```python3 ctfe7ch.py -u L3o -p thisisapassword https://ctf.example.com  -o ./challenges```

* To download CTF challenges with tags, solves, points information:

```python3 ctfe7ch.py -u L3o -p thisisapassword https://ctf.example.com -o ./challenges -v```

* To download CTF challenges with files on MEGA:

```python3 ctfe7ch.py -u L3o -p thisisapassword https://ctf.example.com -o ./challenges --plugin=mega```

* To download CTF challenges with files on MEGA, web and pwn categories only:

```python3 ctfe7ch.py -u L3o -p thisisapassword https://ctf.example.com -o ./challenges --plugin=mega -c web,pwn```

* To download CTF challenges hosted on rCTF, using token for login:

```python3 ctfe7ch.py -t mylogintoken https://ctf.example.com -o ./challenges --platform=rctf ```


<i>Note: There are no examples for Google Drive and Google Cloud Storage because they can be downloaded automatically. We don't need to provide any other switches.</i>

## Version
**Current version is 1.1.0**
