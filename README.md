# CTFe7ch

CTFe7ch is a python tool designed to download Capture The Flag (CTF) challenges and files. It helps CTFers to gather resources from the competition. Now it only supports CTFs hosted on [CTFd](https://github.com/CTFd/CTFd). It may support other frameworks in the future.

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
CTFe7ch depends on the `requests`, `bs4`, `argparse`, and `importlib` python modules.

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
-o            | --output        | Save the files to the directory
-v            | --verbose       | Increase challenge description verbosity, includes tags, solves, and points
-c            | --category      | Specify categories to fetch, split with "`,`" e.g. web,pwn,"vulncon 2020". Default: all
|             | --download-type | Specify where the challenge files come from, e.g. ctfd, mega
-h            | --help          | show the help message and exit

### Examples

* To list all the basic options and switches use -h switch:

```python3 ctfe7ch.py -h```

* To download CTF challenges:

```python3 ctfe7ch.py -u L3o -p thisisapassword https://ctf.example.com  -o ./challenges```

* To download CTF challenges with tags, solves, points information:

```python3 ctfe7ch.py -u L3o -p thisisapassword https://ctf.example.com  -o ./challenges -v```

* To download CTF challenges with files on MEGA:

```python3 ctfe7ch.py -u L3o -p thisisapassword https://ctf.example.com  -o ./challenges --download-type=mega```

* To download CTF challenges with files on MEGA, web and pwn categories only:

```python3 ctfe7ch.py -u L3o -p thisisapassword https://ctf.example.com  -o ./challenges --download-type=mega -c web,pwn```

## Version
**Current version is 1.0**
