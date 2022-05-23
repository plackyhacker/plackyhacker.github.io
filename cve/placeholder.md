# Three CVEs in [OpenSource Software]

While studying the Offensive Security Advanced Web Attacks and Exploitation (WEB-300) course I decided to take a day out and see if I could find any vulnerabilities in open source web applications. I headed over to [website] and found an application written in PHP by a developer who had written apps with vulnerabilities in the past.

I picked the web application that had been updated the most recently (or at least I thought it had) and decided to do some source code review. What I found didn't take very long to exploit; I managed to get remote code execution in about 30 minutes of testing.

Although none of the vulnerabilities are particularly advanced, the third one which got me remote code execution was quite fun! I've documented the vulnerabilities I found in this post.

## Disclosure

I disclosed the vulnerabilities to the developer and to the source code website on which it is published. The developer advised me that he had abandoned the software many years ago and the website owner did not respond to my email.

Although the application isn't widely used I did find three instances with some basic google-fu. I did inform the owners of these sites but again did not recieve a response.

My advice would be not to use this app unless you are willing to put some serious effort in to fixing the vulnerabilities. I only tested a small part of it but I could see in the code that there were many more vulnerabilities.

Okay, on to the sploits!

## CVE-2022-XXXX
### XSS Vulnerability Leading to PHP Session Cookie Exposure

## CVE-2022-XXXX
### SQL Injection Leading to Authentication Bypass

## CVE-2022-XXXX
### Arbitrary File Upload Leading to Remote Code Execution
