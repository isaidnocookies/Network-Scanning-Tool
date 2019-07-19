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
                with open("temp.txt", "w") as tempOutput:
                    tempOutput.write(str(nmapData) + "\n")
                logging.debug("Temp data dumped to file")
            except:
                logging.critical("Temp nmap data failed to save")

            currentTimestamp = str(self.getTimeStamp())
            self.cursor.execute('''UPDATE scans SET status=?, end_timestamp=? WHERE target_file=?''', ("Complete", currentTimestamp, currentTargetFile))
            self.conn.commit()

            print (nmapData)

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

        print (jsonObj)

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

if __name__ == '__main__':

    # parser = argparse.ArgumentParser(description="Nmap automation tool")
    # parser.add_argument('sqlite')
    originalSigint = signal.getsignal(signal.SIGINT)
    signal.signal(signal.SIGINT, exitApplication)

    networkScanner = Network_Scanner()
    networkScanner.loadConfig()
    networkScanner.initializeSqlite()
    networkScanner.initializeSqliteScanData()
    networkScanner.scanFromDB()
    # scanData = networkScanner.nmapScan("target_files/ips_10.0_2019_07_18.txt")
    # print (scanData)
    
