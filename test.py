from pathlib import Path
import os

entries ='/home/harishankar/v2/scanfile/'
for entry in os.listdir(entries):
    if os.path.isfile(os.path.join(entries, entry)):
        print(entry)
