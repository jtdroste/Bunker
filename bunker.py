#!/usr/bin/env python

import os
import subprocess
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
	print('fw_log: Enable or Disable firewall logging')
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
	print('grouplist: Lists all groups that has users')
	print('files: Lists all files currently opened on the machine')
	print('cron: Edit the cron (scheduled tasks) for a user')
	print('sshconfig: Edit the ssh configuration')
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
	
	# Localhost traffic
	os.system('sudo iptables -A INPUT -i lo -j ACCEPT')
	os.system('sudo iptables -A OUTPUT -o lo -j ACCEPT')
	
	# Allow accepted and related traffic
	os.system('sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT')
	
	# Add bunker logging chain
	os.system('sudo iptables -N bunker-log-in-chain')
	os.system('sudo iptables -A INPUT -j bunker-log-in-chain')
	
	os.system('sudo iptables -N bunker-log-out-chain')
	os.system('sudo iptables -A INPUT -j bunker-log-out-chain')
	
	# Add bunker block chain
	os.system('sudo iptables -N bunker-block-chain')
	os.system('sudo iptables -A INPUT -j bunker-block-chain')
	
	# Add bunker input chain
	os.system('sudo iptables -N bunker-input-chain')
	os.system('sudo iptables -A INPUT -j bunker-input-chain')
	
	# Ping
	print('Would you to enable this machine to respond to pings?')
	yn = raw_input('[Y/n]: ')
	
	if ( yn == 'Y' or yn == 'y' ):
		print('The output of a command listing your interfaces and IPs is listed below')
		
		os.system('ifconfig -a')
		
		print('Please carefully type the IP address of the interface you would like to allow incoming and outgoing ping from.')
		ip = raw_input('IP Address: ')
		
		# Ping in
		os.system('sudo iptables -A INPUT -p icmp --icmp-type 8 -s 0/0 -d ' + ip + ' -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT')
		os.system('sudo iptables -A INPUT -p icmp --icmp-type 0 -s 0/0 -d ' + ip + ' -m state --state ESTABLISHED,RELATED -j ACCEPT')
		
		# Ping out
		os.system('sudo iptables -A OUTPUT -p icmp --icmp-type 0 -s ' + ip + ' -d 0/0 -m state --state ESTABLISHED,RELATED -j ACCEPT')
		os.system('sudo iptables -A OUTPUT -p icmp --icmp-type 8 -s ' + ip + ' -d 0/0 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT')
	
	# Log inbound
	print('Would you like to log inbound connections?')
	yn = raw_input('[Y/n]: ')
	
	if ( yn == 'Y' or yn == 'y' ):
		os.system('sudo iptables -A bunker-log-in-chain -m state --state NEW -j LOG --log-prefix "New Connection: "')
	
	# Log outbound
	print('Would you like to log outbound connections?')
	yn = raw_input('[Y/n]: ')
	
	if ( yn == 'Y' or yn == 'y' ):
		os.system('sudo iptables -A bunker-log-out-chain -m state --state NEW -j LOG --log-prefix "New Outbound Connection: "')
	
	os.system('sudo iptables -A INPUT -j DROP')
	
	print('Basic firewall rules has been added. Please allow specific ports through "fw_open"')


def fw_open():
	print('Opening a firewall port...')
	t = raw_input('TCP or UDP Port? ')
	port = raw_input('Which Port? ')
	
	if ( os.system('sudo iptables -S bunker-input-chain > /dev/null 2>&1') == 1 ):
		os.system('sudo iptables -N bunker-input-chain')
		print('')
		print('**NOTE: I did not detect the following chain: bunker-block-chain')
		print('**NOTE: You will have to add a jump to the chain "bunker-block-chain" in your INPUT firewall rules')
		print('**NOTE: Or you can run the fw_secure command, and re-run this command :-)')
		print('')
	
	if ( t == "UDP" or t == "udp" ):
		os.system('sudo iptables -A bunker-input-chain -p udp --dport '+port+' -j ACCEPT')
	else:
		os.system('sudo iptables -A bunker-input-chain -p tcp --dport '+port+' -j ACCEPT')
	
	print('Opened port '+port+'!')


def fw_block():
	print('Blocking an IP address...')
	ip = raw_input('IP Address: ')
	
	if ( os.system('sudo iptables -S bunker-block-chain > /dev/null 2>&1') == 1 ):
		os.system('sudo iptables -N bunker-block-chain')
		print('')
		print('**NOTE: I did not detect the following chain: bunker-block-chain')
		print('**NOTE: You will have to add a jump to the chain "bunker-block-chain" in your INPUT firewall rules')
		print('**NOTE: Or you can run the fw_secure command, and re-run this command :-)')
		print('')
	
	os.system('sudo iptables -A bunker-block-chain -s '+ip+' -j DROP')
	
	print('Blocked IP '+ip+'!')


def fw_log():
	print('Firewall logging')
	print('**NOTICE** This will only work if you setup your firewall using "fw_secure"!')
	
	if ( os.system('sudo iptables -S bunker-log-in-chain > /dev/null 2>&1') == 1 or os.system('sudo iptables -S bunker-log-out-chain > /dev/null 2>&1') == 1 ):
		print('System was not setup with Rapid_Bunker. Can not continue.')
		return 0;
	
	proc1 = subprocess.Popen('sudo iptables -L bunker-log-in-chain | wc -l', stdout=subprocess.PIPE, shell=True)
	(inchain, err1) = proc1.communicate()
	
	proc12= subprocess.Popen('sudo iptables -L bunker-log-out-chain | wc -l', stdout=subprocess.PIPE, shell=True)
	(outchain, err1) = proc2.communicate()
	
	if ( inchain == 2 ):
		print('Logging inbound connections: DISABLED')
	else:
		print('Logging inbound connections: ENABLED')
	
	if ( outchain == 2 ):
		print('Logging outbound connections: DISABLED')
	else:
		print('Logging outbound connections: ENABLED')
	
	print('')
	print('What would you like to do?')
	print('1: Toggle logging inbound connections')
	print('2: Toggle logging outbound connections')
	print('3: Exit this selection (but not the program!)')
	print('')
	
	while True:
		command = int(raw_input("Action: "))
		
		if ( command == 1 ):
			if ( inchain == 2 ):
				# Enable
				os.system('sudo iptables -A bunker-log-in-chain -m state --state NEW -j LOG --log-prefix "New Connection: "')
			else:
				# Disable
				os.system('sudo iptables -F bunker-log-in-chain')
		elif ( command == 2 ):
			if ( outchain == 2 ):
				# Enable
				os.system('sudo iptables -A bunker-log-out-chain -m state --state NEW -j LOG --log-prefix "New Outbound Connection: "')
			else:
				# Disable
				os.system('sudo iptables -F bunker-log-out-chain')
		elif ( command == 3 ):
			return 0
		else:
			print('Unknonw action!')

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
	
	if ( killme.isdigit() ):
		os.system('sudo kill '+killme)
	else:
		os.system('sudo killall '+killme)
	
	print('TODO')


def install():
	apt_test = os.system('which apt-get')
	yum_test = os.system('which yum')
	
	if ( apt_test == 0 ) :
		os.system('sudo apt-get install fail2ban chkrootkit logwatch nmap')
	
	if ( yum_test == 0 ) :
		os.system('sudo yum install fail2ban chkrootkit logwatch nmap')


def last():
	print('Listing last logins')
	
	os.system('last')


def users():
	print('Listing all logged in users')
	
	os.system('who')


def userlist():
	print('Listing all users on this system')
	
	os.system('awk -F\':\' \'{ print $1 }\' /etc/passwd')


def grouplist():
	print('Listing all groups with users assigned to it')
	
	os.system('getent group | awk -F\':\' \'{ if ( $4 != "" ) { print $1 ": " $4 } }\'')


def files():
	print('Listing all files currently open')
	
	os.system('lsof')


def cron():
	print('Listing all scheduled tasks for a user')
	
	user = raw_input('Username: ')
	
	subprocess.call(['sudo', 'crontab', '-e', '-u', user])


def sshconfig():
	subprocess.call(['sudo', 'nano', '/etc/ssh/sshd_config'])


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
  'fw_log': fw_log,
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
  'grouplist': grouplist,
  'files': files,
  'cron': cron,
  'sshconfig': sshconfig,
  
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
  cmd = raw_input('Rapid_Bunker> ')
  
  try:
    functions[cmd]()
  except KeyError:
    print('[ERROR] Unknown command ' + cmd)

  print('')