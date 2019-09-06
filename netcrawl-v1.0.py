# Author: Bobby Williams | <bobby.williams@xxxx>
# Title: NetCrawl
# Version: '1.0'
# Description: This script will discover devices connected via SSH + CDP (Cisco Discovery Protocol)
#   ** Results will be saved to 'results.txt' in same directory
#   ** For SSH failed connections, progress will be saved to 'progress_before_failure.txt' in same directory
# Requirements: Paramiko - 'pip3 install paramiko'
import sys, time, re
import argparse
import paramiko
from getpass import getpass

version = '1.0'
contact = 'bobby.williams@xxxx'

candidates = []
processed = []
results = []

#----------------------------------------------------------------
#  Parser - retrieve IP/hostname from user + provide script info
#----------------------------------------------------------------
def arg_parse():
    parser = argparse.ArgumentParser(description='Site Discovery Crawler v{}\nContact: {}'.format(version, contact), formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('ip', metavar='<IP/hostname>', help='Enter the IP/hostname of the root device')
    args = parser.parse_args()
    return args.ip
#--------------------------------------------
#  Ask for username/password
#--------------------------------------------
def get_user_pass():
    username = input('Username: ')
    passwd = getpass('Password: ')
    return username, passwd
#--------------------------------------------
#  SSH to device and start CDP discovery
#--------------------------------------------
def get_cdp_neighbors(ip, user, pwd):
	ssh = paramiko.SSHClient()
	ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
	try:
		ssh.connect(ip, username=user, password=pwd, port=22)
	except:
		print('SSH connection failed - check authentication..')
		progress_so_far()
		sys.exit(1)
	session = ssh.invoke_shell()
	time.sleep(2)
	print('Initiating crawl from {}..'.format(ip))
	output = session.recv(65535)
	time.sleep(1.3)
	# Set terminal length to 0
	session.send('terminal length 0\n')
	time.sleep(1.3)
	# Execute 'sh cdp neighbors detail'
	session.send('sh cdp neighbors detail\n')
	time.sleep(1.3)
	while session.recv_ready():
		output += session.recv(65535)
		time.sleep(1.3)

	output = str(output)
	# Process output
	process_output(ip, output)

	# Close the session
	session.send('exit\n')
	ssh.close()
	print('Finished crawl for {}'.format(ip))
#--------------------------------------------
#  Process CDP neighbor output
#--------------------------------------------
def process_output(ip, output):
    found = re.findall(r'Device ID[\s\S]+?Support', output)
    if found:
        for i in found:
            device = {}
            # Get the device IP
            get_ip = re.search(r'IP address: \d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', i)
            if get_ip:
                get_ip = get_ip.group()
                splitter = get_ip.split(': ')
                device_ip = splitter[1]
                device["ip"] = device_ip
                # Get the device platform/type
                get_type = re.search(r'Platform[\s\S]+?Interface:', i)
                if get_type:
                    device_type = get_type.group()
                    device_type = device_type.split('Interface')
                    device_type = device_type[0]
                    device_type = device_type.split('Capabilities:')
                    device_type = device_type[0]
                    device_type = device_type.replace(',', '')
                    device["type"] = device_type
                # Get the interface
                get_int = re.search(r'Interface[\s\S]+?,', i)
                if get_int:
                    device_int = get_int.group()
                    device_int = device_int.split()
                    device_int = device_int[1]
                    device_int = device_int.replace(',', '')
                    device["interface"] = device_int

                # Display discovered device to terminal
                print('found device: {} | {}'.format(device["ip"], device["type"]))

                # Root device check - if current found device matches the root device IP,
                # add it to the results list.
                if device["ip"] == root_device_ip:
                    if device not in results:
                        results.append(device)

                # If current run not in candidates list then it has been processed
                # Add to processed and results list if not already there
                if ip not in candidates:
                    if ip not in processed:
                        processed.append(ip)
                    if device not in results:
                        results.append(device)
                
                # If found device not in processed list then add it to candidates
                # list for processing    
                if device["ip"] not in processed:
                    candidates.append(device["ip"])

def progress_so_far():
    # Save progress up until the point of failed device connection
    with open('progress_before_failure.txt', 'a') as fo:
        for i in results:
            if i["ip"] == root_device_ip:
                fo.write('(root){},{},{}\n'.format(i["ip"], i["type"], i["interface"]))
            else:
                fo.write('{},{},{}\n'.format(i["ip"], i["type"], i["interface"]))
    print('Progress before failure saved to: progress_before_failure.txt')

def save_results():
    # Save discovered devices to file
    with open('results.txt', 'a') as fo:
        for i in results:
            if i["ip"] == root_device_ip:
                fo.write('(root){},{},{}\n'.format(i["ip"], i["type"], i["interface"]))
            else:
                fo.write('{},{},{}\n'.format(i["ip"], i["type"], i["interface"]))     
    print('Site discovery complete - results saved to: results.txt')
    
#--------------------------------------------
#  Main func
#--------------------------------------------
def main():
    ip = arg_parse()
    username, passwd = get_user_pass()

    # Root device run
    global root_device_ip
    root_device_ip = ip
    get_cdp_neighbors(ip, username, passwd)

    # Non-root runs
    while candidates:
        ip = candidates.pop()
        get_cdp_neighbors(ip, username, passwd)

    save_results()
    
if __name__ == '__main__':
    main()
