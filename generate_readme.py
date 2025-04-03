#! /usr/bin/env python3

import json
import os
from pprint import pprint

from slugify import slugify

with open('data/pcab_library.json', 'r') as json_file:
    pcap_library = json.load(json_file)

with open('data/tags.json', 'r') as json_file:
    pcap_tags = json.load(json_file)          

cheat_sheets = os.listdir("cheat_sheets")
cheat_sheets.sort()
pcap_library = sorted(pcap_library, key=lambda x: x['title'])
pcap_tags.sort()

with open('README.md', 'w+') as readme:
    readme.write("# Packetlife backup\n")
    readme.write("## Cheat sheets\n\n")
    
    for sheet in cheat_sheets:
        sheet_name = sheet.replace(".pdf", "")
        readme.write(f"- [{sheet_name}](cheat_sheets/{sheet})\n")
    
    readme.write("\n")
    
    readme.write("## Packet captures\n\n")
    
    readme.write("### Tags\n\n")
    
    for tag in pcap_tags:
        readme.write(f"[{tag}](#{slugify(tag)}) - ")
    
    readme.write("\n")
    
    readme.write("### Captures\n\n")
    
    for pcap in pcap_library:
        readme.write(f"- [{pcap['title']}](<pcaps/{pcap['title']}>)\n\n")
        readme.write(f"  duration: {pcap['duration']} - packets: {pcap['packets']} - size: {pcap['size']}\n\n")
        readme.write("  tags:")
        
        
        pcap['tags'].sort()
        for tag in pcap['tags']:
            
            readme.write(f" [{tag}](#{slugify(tag)})")
        
        readme.write("\n\n")
            
        readme.write(f"  {pcap['description']}\n")
        
    
    readme.write("### Grouped by tag\n\n")
    
    for tag in pcap_tags:
        readme.write(f"#### {tag}\n\n")
        
        for pcap in pcap_library:
           if tag in pcap['tags']:
               readme.write(f"- [{pcap['title']}](<pcaps/{pcap['title']}>)\n")
           
        readme.write("\n")
