#! /usr/bin/env python3
import json
import os
from time import sleep

import httpx
from bs4 import BeautifulSoup

archive_url = "https://web.archive.org"

if not os.path.exists("pcaps"):
    os.mkdir("pcaps")
if not os.path.exists("data"):
    os.mkdir("data")

pcap_library = []
unique_tags = set()
rate_limit_count = 0

for pagenumber in range(1,8):
    
    with open(f"html_pages/page_{pagenumber}.html", "r+") as file:
        html = file.read()
        
        bs = BeautifulSoup(html, 'html.parser')
        title_start = bs.find("h1")
        
        packet_capture_divs = title_start.find_all_next(class_=["pull-right"])

        for packet_capture_div in packet_capture_divs:
            
            pcap_data = {}
            
            # Generate the download url
            # Add if_ to the link to get the direct link
            pcap_url = packet_capture_div.find_all("a")[0]
            pcap_url['href'] = pcap_url['href'].replace("/https://packetlife.net", "if_/https://packetlife.net")
            pcap_download_url = f"{archive_url}{pcap_url["href"]}"
        
            # extract the title and size
            pcap_data['title'] = packet_capture_div.find_next("h3").contents[0].strip()

            # get the tags
            pcap_data['tags'] = []
            tags = packet_capture_div.parent.find_all("span", class_="label")
            for tag in tags:
                pcap_data['tags'].append(tag.find("a").contents[0])
                unique_tags.add(tag.find("a").contents[0])
            
            # extract the stats
            pcap_stats = packet_capture_div.parent.find("table").find("tr").find_all("td")
            pcap_data["packets"]  = pcap_stats[0].find("strong").contents[0].strip()
            pcap_data["duration"] = pcap_stats[1].find("strong").contents[0].strip()
            pcap_data["size"]     = packet_capture_div.find_next("h3").find("small").contents[0].strip().replace(u'\xa0', u' ')
            
            # extract the description - might be a p in a div or the next p. check for both
            pcap_description = packet_capture_div.parent.find_all("div")
            
            # sometimes the description is hidden in another div
            if len(pcap_description) > 1:
                pcap_data["description"] = pcap_description[1].find_all("p")[0].contents[0].strip()
            else:
                pcap_data["description"] = packet_capture_div.find_next("p", class_="small").find_next("p").get_text().strip()

            # rate limit is 15/minute. We are taking it slowly per 14/minute
            rate_limit_count += 1

            if rate_limit_count == 12:
                print("sleeping 80 seconds to wait for the rate limiter")
                sleep(80)
                print("continuing...")
                rate_limit_count = 0
            
            # Grab the pcap
            try:
                print(f"Grabbing {pcap_data['title']}")
                pcap = httpx.get(pcap_download_url, timeout=60, follow_redirects=True)
                
            except httpx.ConnectError as exc:
                print("Hit ratelimiter, waiting for 5m30m")
                sleep(330)
                rate_limit_count = 0
                print(f"Grabbing {pcap_data['title']}")
                pcap = httpx.get(pcap_download_url, timeout=60, follow_redirects=True)
                
            
            with open(f"pcaps/{pcap_data['title']}", "wb") as pcap_file:
                pcap_file.write(pcap.content)
            
            pcap_library.append(pcap_data)

with open('data/pcab_library.json', 'w+') as json_file:
    json.dump(pcap_library, json_file)

# convert tags to list
unique_tags = list(unique_tags)
with open('data/tags.json', 'w+') as json_file:
    json.dump(unique_tags, json_file)            
