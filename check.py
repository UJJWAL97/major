import urllib

import seolib
import whois
import re
import dateutil.parser
import datefinder
import datetime
import requests
import ssl, socket

from slimit.parser import Parser
from bs4 import BeautifulSoup
import urlparse
from pyfav import get_favicon_url

link = 'https://www.w3schools.com/js/tryit.asp?filename=tryjs_prompt'
arr = []
domain = link.split('/')
# 1. having_IP_Address  { -1,1 }
try:
    parts = domain[2].split('.')
    temp = len(parts) == 4 and all(0 <= int(part) < 256 for part in parts)
except ValueError:
    temp = False  # one of the 'parts' not convertible to integer
except (AttributeError, TypeError):
    temp = False  # `ip` isn't even a string

if (temp):
    arr.append(1)
else:
    arr.append(-1)

# 2.URL_Length

if (54 > len(link)):
    arr.append(-1)
elif (len(link) > 54 and len(link) < 75):
    arr.append(0)
else:
    arr.append(1)

# 3.tiny url
try:
    resp = urllib.urlopen(link)
    if (link == resp.url):
        arr.append(-1)
    else:
        arr.append(1)
except IOError:
    arr.append(1)

# 4.having_At_Symbol
if ('@' in link):
    arr.append(1)
else:
    arr.append(-1)

# 5.double_slash_redirecting

dslash = link.split('//')
if (len(dslash) > 2):
    arr.append(1)
else:
    arr.append(-1)

# 6.Prefix_Suffix

if ('-' in link):
    arr.append(1)
else:
    arr.append(-1)

# 7.having_Sub_Domain

if (domain[2].count('.') == 2 or domain[2].count('.') == 3):
    arr.append(-1)
elif ('.' in domain[2] == 4):
    arr.append(0)
else:
    arr.append(1)

# 8.SSLfinal_State
try:
    ctx = ssl.create_default_context()
    s = ctx.wrap_socket(socket.socket(), server_hostname=domain[2])
    s.connect((domain[2], 443))
    cert = s.getpeercert()
    subject = dict(x[0] for x in cert['subject'])
    issued_to = subject['commonName']
    issuer = dict(x[0] for x in cert['issuer'])
    issued_by = issuer['commonName']
    arr.append(-1)
except socket.gaierror:
    arr.append(1)

# 9.Domain_registeration_length

w = whois.whois(domain[2])
date = re.findall('Expiration Date:*(.+)', w.text)
final_date = dateutil.parser.parse(date[0])
current_time = datetime.datetime.now()
result_time = final_date.date() - current_time.date()

if result_time.days < 365:
    arr.append(1)
else:
    arr.append(-1)

# 10 favicon
favicon_url = get_favicon_url(link)
if favicon_url:
    arr.append(-1)
else:
    arr.append(1)

# 11 Using Non-Standard Port

if (domain[
    0] == 'http' or 'https' or 'ftp' or 'ssh' or 'telnet' or 'smb' or 'jdbc:sqlserver' or 'jdbc:oracle' or 'jdbc:mysql' or 'rdp'):
    arr.append(-1)
else:
    arr.append(1)
# 12 HTTPS_token

if 'https' in domain[2]:
    arr.append(1)
else:
    arr.append(-1)

# 13 Request_URL

response = requests.get(link)
soup = BeautifulSoup(response.text, 'html.parser')
img_tags = soup.find_all('img')
img_url = [img['src'] for img in img_tags]
total = 0
url = 0
local = 0
for i in img_url:
    try:
        request = requests.head(i)
        if request.status_code == 200:
            url += 1
        else:
            local += 1
    except requests.exceptions.MissingSchema:
        local += 1

    total += 1
if local / total < 0.6:
    arr.append(1)
else:
    arr.append(-1)
# 14 URL_of_Anchor

anchor_tags = soup.find_all('a')
empty = 0
total_a = 0
valid = 0
a_url = [img['href'] for img in anchor_tags]
for i in a_url:
    if 'javascript:void(0);' == i:
        empty += 1
    elif '#' == i:
        empty += 1
    elif '#skip' == i:
        empty += 1
    elif '#content' == i:
        empty += 1
    else:
        valid += 1
    total_a += 1

if empty / float(total_a) < 0.31:
    arr.append(-1)
elif empty / float(total_a) < 0.67:
    arr.append(0)
else:
    arr.append(1)

# 15. Links in <Meta>, <Script> and <Link> tags
total = 0
valid = 0
invalid = 0
meta_tags = soup.find_all('meta')
script_tags = soup.find_all('script')
link_tags = soup.find_all('link')
try:
    meta_content = [img['content'] for img in meta_tags]
except KeyError:
    invalid += 1

for i in meta_content:
    try:
        request = requests.head(i)
        if request.status_code == 200:
            temp_link = i.split('/')
            if temp_link[2] == domain[2]:
                valid += 1
            else:
                invalid += 1
        else:
            valid += 1
    except requests.exceptions.MissingSchema:
        valid += 1

script_content = []
try:
    script_content = [img['src'] for img in script_tags]
except KeyError:
    valid += 1
for i in script_content:
    try:
        request = requests.head(i)
        if request.status_code == 200:
            temp_link = i.split('/')
            if temp_link[2] == domain[2]:
                valid += 1
            else:
                invalid += 1
        else:
            valid += 1
    except requests.exceptions.MissingSchema:
        valid += 1

link_content = []
try:
    link_content = [img['href'] for img in link_tags]
except KeyError:
    valid += 1

for i in link_content:
    try:
        request = requests.head(i)
        if request.status_code == 200:
            temp_link = i.split('/')
            if temp_link[2] == domain[2]:
                valid += 1
            else:
                invalid += 1
        else:
            valid += 1

    except requests.exceptions.MissingSchema:
        valid += 1
total = valid + invalid

if invalid / float(total) < 0.17:
    arr.append(-1)
elif invalid / float(total) < 0.81:
    arr.append(0)
else:
    arr.append(1)

# 16 SFH
arr.append(0)

# 17.Submitting_to_email

link_mailto = soup.find_all('mailto')
link_mail = soup.find_all('mail')

if link_mail or link_mailto:
    arr.append(1)
else:
    arr.append(-1)

# 18 Abnormal url

o = urlparse.urlparse(link)
if o.hostname in link:
    arr.append(-1)
else:
    arr.append(1)

# 19. Website Forwarding
count = 0
response = requests.get(link)
if response.history:
    for resp in response.history:
        count += 1

if count <= 1:
    arr.append(-1)
elif count < 4:
    arr.append(0)
else:
    arr.append(1)

# 20. Status Bar Customization
link_onmouseover = soup.find_all('onmouseover')

if 'window.status' in link_onmouseover:
    arr.append(1)
else:
    arr.append(-1)

# 21.RightClick
link_disable = soup.find_all('event.button==2')

if link_disable:
    arr.append(1)
else:
    arr.append(-1)

# 22 Using Pop-up Window
link_prompt = []
for wrapper in soup.find_all('script'):
    link_prompt.append(wrapper.text)

newlist = []
str1 = ''.join(link_prompt)
parser = Parser()
pattern = r'prompt\("(.*?)"\)'
newlist.append(re.search(pattern, str1).group(1))

if newlist:
    arr.append(1)
else:
    arr.append(-1)

# 23. iframe
iframe_tag = soup.find_all('iframe')

if iframe_tag:
    arr.append(1)
else:
    arr.append(-1)

# 24.Age of Domain
date = re.findall('Creation Date:*(.+)', w.text)
date.append(re.findall('Created On:*(.+)', w.text))
final_date = dateutil.parser.parse(date[0])
current_time = datetime.datetime.now()
result_time = current_time.date() - final_date.date()

if result_time.days < 183:
    arr.append(1)
else:
    arr.append(-1)

# 25 DNS Record
if w.text:
    arr.append(-1)
else:
    arr.append(1)

# 26 Website Traffic
alexa_rank = 0
seo = seolib
alexa_rank = seo.get_alexa(domain[2])

if alexa_rank < 100000 and alexa_rank > 0:
    arr.append(-1)
elif alexa_rank > 100000:
    arr.append(0)
else:
    arr.append(-1)
