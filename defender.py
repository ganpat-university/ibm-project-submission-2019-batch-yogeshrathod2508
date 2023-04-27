import subprocess
import base64

def check_firewall():
    # Get the status of the Windows Firewall profiles
    profiles = ["Domain", "Private", "Public"]
    status = {}

    for profile in profiles:
        cmd = f"Get-NetFirewallProfile -Profile {profile} | Select-Object -ExpandProperty Enabled"
        encoded_cmd = base64.b64encode(cmd.encode("utf-16le")).decode()
        status[profile] = subprocess.check_output(f"powershell.exe -EncodedCommand {encoded_cmd}", shell=True).decode().strip()

    # Print the status of each profile
    for profile in profiles:
        if status[profile] in "True":
            pass
            #print(f"Windows Firewall is currently enabled for the {profile} profile.")
        else:
            subprocess.call(f"powershell.exe Set-NetFirewallProfile -Profile {profile} -Enabled True", shell=True)
            #print(f"Windows Firewall has been enabled for the {profile} profile.")



check_firewall()