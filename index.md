## Sensitive information disclosure vulnerability in D-Link dir-605l B2 2.01mt

Sensitive information disclosure vulnerability exists in D-Link dir-605l B2 2.01mt. An attacker can obtain a user name and password by forging a post request to the / getcfg.php page


## harm

An attacker can access this page without authorization, obtain the user name and password in plaintext, and obtain background management privileges after logging in to the background


## Test method
1. Visit the d-link-dir-605l background login page

![image](https://user-images.githubusercontent.com/90023952/131959536-11a1cf7b-bd26-4ef6-9c52-5ae002c44811.png)

2. Enter any password, then grab the packet and modify the packet content as follows

![image](https://user-images.githubusercontent.com/90023952/131959930-bdc051b1-e234-4803-972d-adf58ddeb554.png)

![image](https://user-images.githubusercontent.com/90023952/131959858-ace71dc7-41c0-4f25-852d-ecc01f2016fd.png)

3.Use the obtained user name and password to successfully log in to the background

![image](https://user-images.githubusercontent.com/90023952/131960031-dc264f90-9e09-48df-9e01-b0860fc3d637.png)
