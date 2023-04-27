# Instead of counting total brute force attacks happened till now, we need to count 3 consecutive attacks made by the same user/IP address
# In the current implementation, we are not able to get IP addresses of the attacker


import wmi
import socket
import win32serviceutil
import psutil
import os
from datetime import datetime
import sys
from termcolor import colored
from tabulate import tabulate
from colour_texts import *

def kill_process():
    # Define the name of the SSH process
    process_name = "sshd.exe"
    # Find all SSH processes
    for proc in psutil.process_iter():
        try:
            # Check if the process name matches the SSH process name
            if proc.name() == process_name:
            # Terminate the process
                try:
                    os.kill(proc.pid, 9)
                except:
                    print("Failed to kill process: " + proc.name())
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

# Create a WMI object
wmi_obj = wmi.WMI()

# Define the query to retrieve security event logs
query = "SELECT * FROM Win32_NTLogEvent WHERE Logfile = 'Security' and EventCode = 4625"

print((colored('\n+++ Analyzing security event logs +++', 'green', attrs=['bold'])))
print()

# Execute the query and retrieve the results
logs = wmi_obj.query(query)

count = 0
table = []
headers = ['Event Code', 'Timestamp', 'Computer Name']


for log in logs:
    count += 1
    # print(f"Event ID: {log.EventCode}\nMessage: {log.TimeGenerated}\nComputer Name: {log.ComputerName}")
    table.append([log.EventCode,log.TimeGenerated,log.ComputerName])

print(tabulate(table, headers=headers))
print()

if count >= 5:
    print(red("Brute Force using SSH Detected!!!","CRITICAL"))
    service_status = win32serviceutil.QueryServiceStatus('sshd')[1]
    if service_status == 1:  ## Means the service is not running
        print(cyan("SSH service is currently not running!","INFO"))
    else:  ## The service is running
        print(cyan("SSH service is running...","INFO"))
        print(red("Closing port 22...","CRITICAL"))
        port = 22
        win32serviceutil.StopService("sshd")
        print(green("Service Terminated successfully!","SUCCESS"))
        kill_process()
            
        
