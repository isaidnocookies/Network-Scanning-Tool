#!/usr/bin/python3

import sys, os, subprocess, signal
import datetime, time
import json
import logging
import argparse
import xmltodict
import xml.etree.ElementTree as ET
import time, datetime
import sqlite3
import pickle

class Network_Scanner:
    def __init__(self):
        """
        Constructor:
            Establishes timestamp for instance, logging, and initializing some instance variables.
        """
        self.timestamp = ('{:%Y-%m-%d_%H-%M-%S}'.format(datetime.datetime.now()))
        logging.basicConfig(level=logging.DEBUG, filename="scanner.log", format='%(levelname)s - %(asctime)s - %(message)s')
        logging.getLogger().addHandler(logging.StreamHandler(sys.stdout))

        self.targetFiles = []
        self.dbInit = False
        self.config = {}



    def __del__(self):
        """
        Destructor:
            Attempts to close database connection when instance is destroyed.
        """
        if (self.dbInit == True):
            self.conn.close()



    def getConfig(self):
        """
        Returns the configuration object. REQUIRES loadConfig to be called
        on the object for initialization.

        Returns:
            Object - {}
                Return the configuration object from the class instance.
        """
        return self.config



    def getTargetFiles(self):
        """
        Returns the target filenames. REQUIRES loadTargetFiles to be called
        on the object for initialization.

        Returns:
            Array of strings - [strings]
                Returns an array of strings representing all of the target lists
        """
        return self.targetFiles



    def loadConfig(self, filename='./config.json'):
        """
        Sets the configuration within the class instance.

        Parameters:
            filename : string
                Filename of the configuration (json) file.
                Defaults to config.json in the scripts root directory

        Returns:
            N/A
        """
        logging.debug("Loading configuration file: \"%s\"", filename)
        try:
            with open(filename) as json_config_file:
                self.config = json.load(json_config_file)
        except:
            logging.critical("Exception occured - Failed to open config file", exc_info=True)

        self.loadTargetFiles()



    def nmapScan(self, target_file):
        """
        Runs an nmap scan with the -sT, -Pn flags on the ip addresses included in the specified target file.
        The results are parsed from xml to a json object for later manipulation and storage.
        Nmap scans on the ports specified in the configuration file.

        Parameters:
            target_file : string
                Filename of the target file. Ip addresses / networks are pulled from this file. Any format
                compatible with nmap input lists can be used

        Returns:
            Object - json
                Nmap data that has been converted from the XML dat
        """
        strPorts = [str(port) for port in self.config['ports']]
        strPorts = ",".join(strPorts)

        try:
            xmlOutput = subprocess.check_output(["nmap", "-sT", "-Pn", "-p", strPorts, "-iL", target_file, "-oX", "-"])
            xmlData = xmlOutput.decode('UTF-8')
            nmapData = Network_Scanner.parseNmapXml(xmlData)

            return nmapData
        except:
            logging.critical("NMAP scan failed!", exc_info=True)
            sys.exit("Nmap scan failed")



    def loadTargetFiles(self):
        """
        Loads files from the target directory specified in the configuration file. This will set the input files
        to the targetFiles variable (array of strings) within the instance.

        Parameters:
            N/A

        Returns:
            Boolean
                Returns if the function was success in pulling the files from the target_directory
        """
        try:
            targetFileDir = networkScanner.getConfig()['target_directory']
            targetFiles = [targetFile for targetFile in os.listdir(targetFileDir) if os.path.isfile(os.path.join(targetFileDir, targetFile))]

            self.targetFiles = targetFiles
            return True
        except:
            logging.critical("Failed to load target files")
        return False



    def initializeSqlite(self, filename=""):
        """
        Initializes the SQLite database. This function connects to / creates the sqlite database file and creates
        the status table that holds the associated scans

        Parameters:
            Filname : string
                Filename associated with the sqlite database. If this does not exist, the db will be created.

        Returns:
            Boolean
                Returns if the function was success in pulling the files from the target_directory
        """
        if (self.dbInit == True):
            return True

        dbFilename = filename
        if (dbFilename == ""):
            dbFilename = self.getConfig()['name']
        dbFilename = dbFilename.replace(" ", "") + ".db"

        self.conn = sqlite3.connect(dbFilename)
        logging.debug("Connected to Sqlite Database")
        self.cursor = self.conn.cursor()

        self.cursor.execute('''CREATE TABLE IF NOT EXISTS scans(target_file TEXT, status TEXT, start_timestamp TEXT, end_timestamp TEXT)''')
        self.conn.commit()
        self.dbInit = True



    def initializeSqliteScanData(self):
        """
        Initializes the database and populates the scans table with data from the target_directory.
        NOTE - This will drop the data from the existing scans table
        This function generates the scans table - (target_file, status, start_timestamp, end_timestamp)

        Parameters:
            N/A

        Returns:
            N/A
        """
        self.cursor.execute('''DELETE FROM scans''')
        for targetFile in self.targetFiles:
            self.cursor.execute('''INSERT INTO scans(target_file, status, start_timestamp, end_timestamp) VALUES(?,?,?,?)''', (targetFile, "Pending", "null", "null"))

        self.conn.commit()



    def saveDataInDatabase(self, targetFilename, scanData):
        """
        Saves data to the database in the appropiate table. Each table corresponds to an individual scan.
        DB Schema - (ip_address TEXT, hostname TEXT, port TEXT, protocol TEXT, service TEXT, state TEXT)

        Parameters:
            targetFilename : string
                target filename associated with the completed scan. This will become the scan's table name
            scanData : Object
                The data associated with the completed nmap scan. This will be in JSON / Object format from the XML parsing

        Returns:
            N/A
        """
        if (not self.dbInit):
            self.initializeSqlite()
        createQuery = "CREATE TABLE IF NOT EXISTS " + targetFilename.replace(".","_") + " (ip_address TEXT, hostname TEXT, port TEXT, protocol TEXT, service TEXT, state TEXT)"
        self.cursor.execute(createQuery)
        hosts = scanData["nmaprun"]["host"]
        hostList = []

        # Hosts can be an object or array of objects based on xml parsing.
        # Standardize the hosts object to a list
        if (type(hosts) != type([])):
            hostList = [hosts]
        else:
            hostList = hosts

        for host in hostList:
            address = host["address"]["@addr"]
            hostname = host["hostnames"]
            ports = host["ports"]["port"]
            portList = []

            # Ports can be an object or array of objects based on the xml parsing.
            # Standardize the hosts object to a list
            if (type(ports) == type([])):
                portList = ports
            else:
                portList = [ports]

            for port in portList:
                if (port["state"]["@state"] == "open"):
                    portNum = port["@portid"]
                    portProtocol = port["@protocol"]
                    portService = port["service"]["@name"]
                    portState = port["state"]["@state"]

                    insertQuery = "INSERT INTO {tableName} ({ip}, {hostname}, {port}, {protocol}, {service}, {state})".format(tableName=targetFilename, ip=address, hostname=hostname, port=portNum, protocol=portProtocol, service=portService, state=portState)
                    self.cursor.execute(insertQuery)



    def scanFromDB(self):
        """
        Runs nmap scans from pending entries in the database. This function will loop through the database scan entries
        and run scans associated with pending target lists. If there is an In Progress scan, it will not resume it -- yet

        This function will also dump scan data into a temp directory. Each scan will be associated with an output dump (in
        the Object format) in the specified folder.

        This function calls the saveDataInDatabase function and will initialize the Sqlite database if the dbInit variable
        has not been set.

        Parameters:
            N/A

        Returns:
            N/A
        """
        if (not self.dbInit):
            self.initializeSqlite()

        continueScanning = True
        while continueScanning:
            self.cursor.execute('''SELECT COUNT(target_file) FROM scans WHERE status="Pending"''')
            pendingTargets = self.cursor.fetchone()[0]

            if (int(pendingTargets) == 0):
                continueScanning = False
                continue

            self.cursor.execute('''SELECT * FROM scans WHERE status=="Pending" LIMIT 1''')
            scanEntry = self.cursor.fetchall()
            
            currentTargetFile = scanEntry[0][0]
            currentTimestamp = str(self.getTimeStamp())
            self.cursor.execute('''UPDATE scans SET status=?, start_timestamp=? WHERE target_file=?''', ("In Progress", currentTimestamp, currentTargetFile))
            self.conn.commit()

            # Start scan with file
            nmapData = self.nmapScan("./target_files/" + currentTargetFile)
            
            try:
                tempFilename = "./temp/temp_{}".format(currentTargetFile)
                with open(tempFilename, "w") as tempOutput:
                    tempOutput.write(str(nmapData) + "\n")
                logging.debug("Temp data dumped to file: {}".format(tempFilename))
            except:
                logging.critical("Temp nmap data failed to save")

            currentTimestamp = str(self.getTimeStamp())
            self.cursor.execute('''UPDATE scans SET status=?, end_timestamp=? WHERE target_file=?''', ("Complete", currentTimestamp, currentTargetFile))
            self.conn.commit()

            self.saveDataInDatabase(currentTargetFile, nmapData)



    @staticmethod
    def checkIfFileExists(filename):
        """
        Simple function to check if a file exists

        Parameters:
            filename : string
                filename to be checked

        Returns:
            Boolean
                Whether or not the file exists
        """
        try:
            if os.path.exists(filename):
                return True
            return False
        except:
            return False



    @staticmethod
    def getTimeStamp(iIncludeTime=True):
        """
        Simple function to generate a timestamp

        Parameters:
            iIncludeTime : Boolean
                Whether or not the time is included with the date timestamp

        Returns:
            String
                Formatted timestamp
        """
        timeStr = ""
        theTime = time.time()
        if (iIncludeTime):
            timeStr = datetime.datetime.fromtimestamp(theTime).strftime('%Y_%m_%d_%H:%M:%S')
        else:
            timeStr = datetime.datetime.fromtimestamp(theTime).strftime('%Y_%m_%d')

        return timeStr



    @staticmethod
    def parseNmapXml(xmlData):
        """
        Parses the XML data exported from the nmap scan. This function converts the xml document to
        an object to be parsed and saved to the database

        Parameters:
            xmlData : String
                String dump of the xml output from nmap

        Returns:
            Object - JSON
                Object from the xml document
        """
        parsedXmlData = ET.fromstring(xmlData)
        xmlstr = ET.tostring(parsedXmlData, encoding='utf8', method='xml')
        data_dict = dict(xmltodict.parse(xmlstr))
        jsonObj = json.dumps(data_dict, indent=4)

        return json.loads(jsonObj)



def exitApplication(sig_num, frame):
    """
    Catches SIGINT in order to provide a place for graceful terminations during scans.

    Parameters:
        sign_num : int
            Signal integer
        frame : Object
            Current stack frame

    Returns:
        N/A
    """
    signal.signal(signal.SIGINT, originalSigint)

    try:
        if input("\nReally quit? (y/n): ").lower().startswith('y'):
            sys.exit(1)

    except KeyboardInterrupt:
        print("Exiting application..")
        sys.exit(1)
        
    signal.signal(signal.SIGINT, exitApplication)



if __name__ == '__main__':
    """
    Main function for Network_Scanner.
    """
    originalSigint = signal.getsignal(signal.SIGINT)
    signal.signal(signal.SIGINT, exitApplication)

    parser = argparse.ArgumentParser(description="Nmap automation tool")
    parser.add_argument('--init', help="Resets and clears the database scans. This will overwrite data within existing database", action="store_true")
    parser.add_argument('--config', help="Configuration file to be used for scans")
    parser.add_argument('--db', help="Filename for SQLite database. Default is \"nmapScan.db\"")
    arguments = parser.parse_args()
    
    networkScanner = Network_Scanner()
    
    if arguments.config:
        networkScanner.loadConfig(arguments.config)
    else:
        networkScanner.loadConfig()

    if arguments.db:
        networkScanner.initializeSqlite(arguments.db)
    else:
        networkScanner.initializeSqlite()
    
    if arguments.init:
        networkScanner.initializeSqliteScanData()
        
    networkScanner.scanFromDB()