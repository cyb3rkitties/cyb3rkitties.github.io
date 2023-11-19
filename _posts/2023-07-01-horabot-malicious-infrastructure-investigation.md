---
title: Horabot - Malicious Infrastructure Investigation
author: al3x
date: 2023-07-01 06:25:00 -0600
categories: [research]
tags: [malware analysis, threat hunting, osint, malicious infrastructure]
---

After brainstorming for quite a while and getting incredibly excited for obtaining research access to [Censys.io Search](https://search.censys.io/), I saw a very interesting report from the great folks at [Cisco Talos](https://talosintelligence.com/) on a [new phishing campaign they track as Horabot](https://blog.talosintelligence.com/new-horabot-targets-americas/) and decided it was time to dig into an investigation and get lost in the many rabbit holes of threat hunting.

My starting points were the [Indicators of Compromise (IOCs) shared by the Talos team](https://github.com/Cisco-Talos/IOCs/tree/main/2023/05/new-horabot-targets-americas.txt):

### IP addresses

- 139[.]177[.]193[.]74
- 185[.]45[.]195[.]226
- 216[.]238[.]70[.]224
- 51[.]38[.]235[.]152
- 137[.]220[.]53[.]87
- 212[.]46[.]38[.]43
- 191[.]101[.]2[.]101

### Domains
- tributaria[.]website
- facturacionmarzo[.]cloud
- m9b4s2[.]site
- wiqp[.]xyz
- ckws[.]info
- amarte[.]store

I decided to start from the last domain name, amarte[.]store and look it up on [URLScan.io](https://urlscan.io/). The search revealed the IP address associated with the domain, 89[.]117[.]37[.]61, as well as a script at a very specific URL:

![amarte.store-urlscan-ip](horabot/amarte.store-urlscan-ip.png)

![amarte.store-script](horabot/amarte.store-script.png)

I used the IP address for a Censys search, which confirmed the relationship and revealed the new domain **maio23[.]com** among the DNS names that link back to 89[.]117[.]37[.]61:

![maio23.com](horabot/maio23.com.png)

Looking at the "Explore" tab on Censys, I could see all the relationships between this IP address, domains, and certificates:

![89.117.37.61_explore_full](horabot/89.117.37.61_explore_full.png)

The SHA256 of the TLS certificate associated with port 443 is also common between amarte[.]storeand maio23[.]com:

![maio23-cert](horabot/maio23-cert.png)

Even though it looks like we got to a dead end, I went back to URLScan and looked up the IP address directly, finding something quite curious:

![factoras.westeurope](horabot/factoras.westeurope.png)

Looking at the URL history and HTTP transactions of this URL, another domain pops up: **facturaion[.]sbs**:

![facturas.details](horabot/facturas.details.png)
![facturas.details2](horabot/facturas.details2.png)

Moreover, if we look at the screenshot that was taken at the time of the scan, we'll see that it's consistent with the campaign content, and includes an invite to download what [Talos reported as a malicious RAR file](https://blog.talosintelligence.com/new-horabot-targets-americas/):

![facturas-screenshot](horabot/facturas-screenshot.png)

 With a new domain in hand, we pivot back to Censys and find the Ip associated with this domain as well as another domain name **f14.world** and an IP associated with it: **154[.]49[.]243[.]254**, connected through common certificate hashes:

![64.176.9.168_explore](horabot/64.176.9.168_explore.png)

Focusing on the new IP, which shows the same services of the others (ports 22, 80, and 443), we can confirm the connection between the two domains as well as acquire some extra information.

![154.49.9.168.details](horabot/154.49.9.168.details.png)

Please, note that this screenshot is taken from my notes: unfortunately, going back to Censys for more, I found out that-surprise surprise-services on this last IP were recently taken down:

![154.49.9.168.services](horabot/154.49.9.168.services.png)

This is by no means the end of the research, though. To this point, we only pivoted using IP addresses and domain names, but we have so much information to dig through and use for further research. This includes JARM fingerprints, patterns derived from certificate information, and so much more.

Until next time!
