import psutil
import os
import win32api
import win32con
import os
import hashlib
import requests
from termcolor import colored
from colour_texts import *

file = []
def check_vt(path,pid):
    

    # Your VirusTotal API key
    api_key = '34fe5a90fbc3a1afce8a2283f5846ecb20665c2c54a42763b207b544f3cce5ba'

    # Calculate the MD5 hash for each file
    hash_dict = {}
    try:
        with open(path, 'rb') as f:
            file_hash = hashlib.md5(f.read()).hexdigest()
            hash_dict[path] = file_hash
    except:
        # print(yellow("unable to get hash of the file","NOT FOUND"))
        pass

    # Send each hash to VirusTotal and print the results
    for path, file_hash in hash_dict.items():
        print(f"File: {path}")
        print(f"MD5 hash: {file_hash}")

        # Check the hash with VirusTotal
        params = {'apikey': api_key, 'resource': file_hash}
        response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params)
        if response.status_code == 200:
            report = response.json()
            if report['response_code'] == 1:
                print(f"Detected by {colored(report['positives'],'red', attrs=['bold'])} out of {colored(report['total'],'red', attrs=['bold'])} antivirus engines on VirusTotal.\n")
                if report['positives'] != 0:
                    try:
                        print(f"Process: {path},  Pid: {pid} Terminated")
                        process = psutil.Process(pid)
                        process.terminate()
                    except psutil.NoSuchProcess:
                        print(f"No process found with PID {pid}")
            else:
                print("Not detected by any antivirus engines on VirusTotal\n")
        else:
            print(f"Error checking hash with VirusTotal: {response.status_code}\n")

while True:
    for proc in psutil.process_iter(['pid', 'name', 'username']):
        try:
            pinfo = proc.as_dict(attrs=['pid', 'exe', 'username'])
        except psutil.NoSuchProcess:
            pass
        else:
            
            if pinfo['exe'] not in file:
                check_vt(pinfo['exe'],pinfo['pid'])
            file.append(pinfo['exe'])