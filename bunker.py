#!/usr/bin/env python

import os
# ---------------------
# Rapid_Bunker
# 
# By James Droste <james@droste.im>
# Based on Rapid_Bunker by Brian Wilcox
# ---------------------

def help():
	print('Rapid_Bunker Command List:')
	print('')
	
	print('General Commands:')
	print('help: This command (lists all commands)')
	print('version: Prints out the system version, and author')
	print('exit: Exits the program')
	
	print('Firewall & Ports:')
	print('fw: Lists all firewall rules')
	print('fw_secure: Implements *BASIC* firewall rules')
	print('fw_open: Opens a firewall port to connect to')
	print('fw_block: Blocks an IP')
	print('ports: Lists all open/listening connections')
	print('')
	
	print('Processes:')
	print('snitch: Shows what processes are connecting to a server')
	print('proc: Lists all processes by all users')
	print('kill: Kills a process by a name or PID')
	print('')
	
	print('Hardening:')
	print('install: Installs common security applications (fail2ban, logwatch, nmap)')
	print('')
	
	print('Other:')
	print('last: Lists the last logins to the machine')
	print('users: Lists all currently logged in users')
	print('userlist: Lists all users on the machine')
	print('files: Lists all files currently opened on the machine')
	print('')

def version():
	print('Rapid_Bunker v0.1-BETA')
	print('Author: James Droste <james@droste.im>')
	print('Based on Rapid_Bunker by Brian Wilcox')

def fw():
	print('Listing firewall rules:\n')
	
	os.system('sudo iptables --list')
	
	print('-------')

def fw_secure():
	print('Implementing basic firewall rules:\n')
	
	os.system('sudo iptables -F')
	os.system('sudo iptables -A INPUT -i lo -j ACCEPT')
	os.system('sudo iptables -A OUTPUT -o lo -j ACCEPT')
	os.system('sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT')
	
	# Ping
	print('Would you to enable this machine to respond to pings?')
	yn = raw_input('[Y/n]: ')
	
	if ( yn == 'Y' or yn == 'y' ):
		print('The output of a command listing your interfaces and IPs is listed below')
		
		os.system('ifconfig -a')
		
		print('Please carefully type the IP address of the interface you would like to allow incoming and outgoing ping from.')
		ip = raw_input('IP Address: ')
		os.system('sudo iptables -A INPUT -p icmp --icmp-type 8 -s 0/0 -d ' + ip + ' -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT')
		os.system('sudo iptables -A OUTPUT -p icmp --icmp-type 0 -s ' + ip + ' -d 0/0 -m state --state ESTABLISHED,RELATED -j ACCEPT')
		os.system('sudo iptables -A OUTPUT -p icmp --icmp-type 8 -s ' + ip + ' -d 0/0 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT')
		os.system('sudo iptables -A INPUT -p icmp --icmp-type 0 -s 0/0 -d ' + ip + ' -m state --state ESTABLISHED,RELATED -j ACCEPT')
	
	os.system('sudo iptables -A INPUT -j DROP')
	
	print('Basic firewall rules has been added. Please allow specific ports through "fw_open"')

def fw_open():
	print('Opening a firewall port...')
	t = raw_input('TCP or UDP Port? ')
	port = raw_inpit('Which Port? ')
	
	if ( t == "UDP" or t == "udp" ):
		os.system('sudo iptables -A INPUT -p udp --dport '+port+' -j ACCEPT')
	else:
		os.system('sudo iptables -A INPUT -p tcp --dport '+port+' -j ACCEPT')
	
	print('Opened port '+port+'!')

def fw_block():
	print('Blocking an IP address...')
	ip = raw_input('IP Address: ')
	
	os.system('sudo iptables -A INPUT -s '+ip+' -j DROP')
	
	print('Blocked IP '+ip+'!')

def ports():
	print('Listing all active or listening connections:')
	
	os.system('netstat --inet -a')

def snitch():
	print('Showing what processes are connecting to the server:')
	
	os.system('lsof -i')

def proc():
	print('Listing all running processes')
	
	os.system('ps -face')

def kill():
	print('Killing a process. What is the process name or id?')
	
	killme = raw_input('Process Name/ID: ')
	
	print('TODO')

def install():
	print('TODO')

def last():
	print('Listing last logins')
	
	os.system('last')

def users():
	print('Listing all logged in users')
	
	os.system('who')

def userlist():
	print('Listing all users on this system')
	
	os.system('grep -o \'^[^:]*\' /etc/passwd')

def files():
	print('Listing all files currently open')
	
	os.system('lsof')

# Function Map
functions = {
  # General
  'help': help,
  'version': version,
  
  # Firewall
  'fw': fw,
  'fw_secure': fw_secure,
  'fw_open': fw_open,
  'fw_block': fw_block,
  'ports': ports,
  
  # Processes
  'snitch': snitch,
  'proc': proc,
  'kill': kill,
  
  # Hardening
  'install': install,
  
  # Other:
  'last': last,
  'users': users,
  'userlist': userlist,
  'files': files,
  
  # More general...
  'quit': exit,
  'exit': exit,
  'q': exit
}

# Actually start the program loop
print('Welcome to Rapid Bunker!')
print('Rapid Bunker comes with ABSOLUTELY NO WARRANTY, use at your own risk!\n')

help()

while True:
  cmd = raw_input('Rapid_Bunker > ')
  
  try:
    functions[cmd]()
  except KeyError:
    print('[ERROR] Unknown command ' + cmd)

  print('')