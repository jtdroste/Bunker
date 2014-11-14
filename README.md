Bunker
============

A Python utility that allows for the rapid deployment of iptables, and provides a common simple interface to security, system administration, and forensics related Linux utilities.  Originally by [Bryan Wilcox](https://github.com/briwilcox), this script was converted to python, and additional utilities were added.

# Commands / Usage

General:

	help: This command (lists all commands)
	version: Prints out the system version, and author
	exit: Exits the program

Firewall & Ports:

	fw: Lists all firewall rules
	fw_secure: Implements *BASIC* firewall rules
	fw_open: Opens a firewall port to connect to
	fw_block: Blocks an IP
	fw_log: Enable or Disable firewall logging
	ports: Lists all open/listening connections

Processes:

	snitch: Shows what processes are connecting to a server
	proc: Lists all processes by all users
	kill: Kills a process by a name or PID

Hardening:

	install: Installs common security applications (fail2ban, logwatch, nmap)

Other:
	last: Lists the last logins to the machine
	users: Lists all currently logged in users
	userlist: Lists all users on the machine
	grouplist: Lists all groups that has users
	files: Lists all files currently opened on the machine
	cron: Edit the cron (scheduled tasks) for a user
	sshconfig: Edit the ssh configuration

# Why write this utility?

Originally I was told about this tool days before our network defense competition.  After seeing it's potential in getting students quickly acquainted with system security and hardening, I decided to fork it and include my own commands as well.  This also served as a tool for me to get acquainted with python programming, so please excuse the bad practices/code.

# Installation

Getting and executing the code should be as simple as:

    wget https://raw.github.com/jtdroste/Bunker/master/bunker.py

    chmod +x bunker.py

    ./bunker.py


# License

Licensed under the BSD license included on the Bunker github repository.

# Misc

To contact the original author: http://brianmwilcox.com

To contact the Bunker's current author: https://james.droste.im
