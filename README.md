# Network Scanning Automation Tool

    usage: Network_Scanner.py [-h] [--init] [--config CONFIG] [--db DB]

optional arguments:
 `-h, --help`
  Show this help message and exit
    
`--init`
Resets and clears the database scans. This will overwrite data within existing database

`--config CONFIG` 
Configuration file to be used for scans   

`--db DB`
Filename for SQLite database. Default is "nmapScan.db"

#

Scanning tool runs nmap to scan ranges included in target files. Each target file will be run through it's own scan and added to the database. Database includes one table for scan status and information (start timestamp, end timestamp, status, and filename) and one table per target-file range.

Each scan is dumped to a "temp" to ensure data is saved regardless of if the scans are propery imported into the database tables.

#