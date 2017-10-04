Catalog Project
!/usr/bin/env python

Prerequisites
	Python
	application.py
	database_setup.py
    addItems.py
    Template files
	Virtual Machine
	
Installing
	Download and install VirtualBox and Vagrant
	Inside the vagrant subdirectory run "vagrant up" and then "vagrant ssh"
    Run "python database_setup.py" to create the database
    Run "addItems.py" to populate the database with dummy data
    (Populated Database is already included)
	
Run
	Run "python application.py" and go to http://localhost:8000 in your preferred browser