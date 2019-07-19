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
        self.timestamp = ('{:%Y-%m-%d_%H-%M-%S}'.format(datetime.datetime.now()))
        logging.basicConfig(level=logging.DEBUG, filename="scanner.log", format='%(levelname)s - %(asctime)s - %(message)s')
        logging.getLogger().addHandler(logging.StreamHandler(sys.stdout))

        self.targetFiles = []
        self.dbInit = False



    def __del__(self):
        if (self.dbInit == True):
            self.conn.close()



    def getConfig(self):
        return self.config



    def getTargetFiles(self):
        return self.targetFiles



    def loadConfig(self, filename='./config.json'):
        logging.debug("Loading configuration file: \"%s\"", filename)
        try:
            with open(filename) as json_config_file:
                self.config = json.load(json_config_file)
        except:
            logging.critical("Exception occured - Failed to open config file", exc_info=True)

        self.loadTargetFiles()



    def nmapScan(self, target_file):
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
        try:
            targetFileDir = networkScanner.getConfig()['target_directory']
            targetFiles = [targetFile for targetFile in os.listdir(targetFileDir) if os.path.isfile(os.path.join(targetFileDir, targetFile))]

            self.targetFiles = targetFiles
            return True
        except:
            logging.critical("Failed to load target files")
        return False



    def initializeSqlite(self, filename="nmapScan.db"):
        if (self.dbInit == True):
            return True

        self.conn = sqlite3.connect(filename)
        logging.debug("Connected to Sqlite Database")
        self.cursor = self.conn.cursor()

        self.cursor.execute('''CREATE TABLE IF NOT EXISTS scans(target_file TEXT, status TEXT, start_timestamp TEXT, end_timestamp TEXT)''')
        self.conn.commit()
        self.dbInit = True



    def initializeSqliteScanData(self):
        self.cursor.execute('''DELETE FROM scans''')
        for targetFile in self.targetFiles:
            self.cursor.execute('''INSERT INTO scans(target_file, status, start_timestamp, end_timestamp) VALUES(?,?,?,?)''', (targetFile, "Pending", "null", "null"))

        self.conn.commit()



    def saveDataInDatabase(self, targetFilename, scanData):
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
    def getTimeStamp(iIncludeTime=True):
        timeStr = ""
        theTime = time.time()
        if (iIncludeTime):
            timeStr = datetime.datetime.fromtimestamp(theTime).strftime('%Y_%m_%d_%H:%M:%S')
        else:
            timeStr = datetime.datetime.fromtimestamp(theTime).strftime('%Y_%m_%d')

        return timeStr



    @staticmethod
    def parseNmapXml(xmlData):
        parsedXmlData = ET.fromstring(xmlData)
        xmlstr = ET.tostring(parsedXmlData, encoding='utf8', method='xml')
        data_dict = dict(xmltodict.parse(xmlstr))
        jsonObj = json.dumps(data_dict, indent=4)

        return json.loads(jsonObj)



def exitApplication(sig_num, frame):
    signal.signal(signal.SIGINT, originalSigint)

    try:
        if input("\nReally quit? (y/n): ").lower().startswith('y'):
            sys.exit(1)

    except KeyboardInterrupt:
        print("Exiting application..")
        sys.exit(1)
        
    signal.signal(signal.SIGINT, exitApplication)



def checkIfFileExists(filename):
    if os.path.exists(filename):
        return True
    return False



if __name__ == '__main__':
    originalSigint = signal.getsignal(signal.SIGINT)
    signal.signal(signal.SIGINT, exitApplication)

    parser = argparse.ArgumentParser(description="Nmap automation tool")
    parser.add_argument('--init', help="Resets and clears the database scans. This will overwrite data within existing database", action="store_true")
    parser.add_argument('--config', help="Configuration file to be used for scans")
    parser.add_argument('--db', help="Filename for SQLite database. Default is \"nmapScan.db\"")
    arguments = parser.parse_args()
    
    networkScanner = Network_Scanner()

    if arguments.db:
        if checkIfFileExists(arguments.db) and arguments.init:
            print("Database already exists")
            sys.exit(1)

        networkScanner.initializeSqlite(arguments.db)
    else:
        if checkIfFileExists("nmapScan.db") and arguments.init:
            print("Database already exists")
            sys.exit(1)

        networkScanner.initializeSqlite()
    
    if arguments.config:
        networkScanner.loadConfig(arguments.config)
    else:
        networkScanner.loadConfig()

    if arguments.init:
        networkScanner.initializeSqliteScanData()
        
    networkScanner.scanFromDB()