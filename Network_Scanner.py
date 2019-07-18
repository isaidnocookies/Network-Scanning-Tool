#!/usr/bin/python3

import sys
import datetime, time
import os
import subprocess
import json
import logging
import argparse
import xmltodict
import xml.etree.ElementTree as ET
import sqlite3

class Network_Scanner:
    def __init__(self):
        self.timestamp = ('{:%Y-%m-%d_%H-%M-%S}'.format(datetime.datetime.now()))
        logging.basicConfig(level=logging.DEBUG, filename="scanner.log", format='%(levelname)s - %(asctime)s - %(message)s')
        logging.getLogger().addHandler(logging.StreamHandler(sys.stdout))

        self.inputFiles = []
        self.dbInit = False

    def __del__(self):
        if (self.dbInit):
            self.conn.close()

    def getConfig(self):
        return self.config

    def getTargetFiles(self):
        return self.inputFiles

    def loadConfig(self, filename='./config.json'):
        logging.debug("Loading configuration file: \"%s\"", filename)
        try:
            with open(filename) as json_config_file:
                self.config = json.load(json_config_file)
        except:
            logging.critical("Exception occured - Failed to open config file", exc_info=True)

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

            self.inputFiles = targetFiles
            return True
        except:
            logging.critical("Failed to load target files")
        return False

    def initializeSqlite(self, filename="nmapScan.db"):
        if (self.dbInit):
            return True

        self.conn = sqlite3.connect(filename)
        logging.debug("Connected to Sqlite Database")
        self.cursor = self.conn.cursor()

        self.cursor.execute('''CREATE TABLE IF NOT EXISTS scans
             (subnet text, target_file text, status text, start_timestamp text, end_timestamp)''')
        self.conn.commit()

    def initializeSqliteScanData(self):
        print ("do stuff here")

    @staticmethod
    def parseNmapXml(xmlData):
        parsedXmlData = ET.fromstring(xmlData)
        xmlstr = ET.tostring(parsedXmlData, encoding='utf8', method='xml')
        data_dict = dict(xmltodict.parse(xmlstr))
        jsonObj = json.dumps(data_dict, indent=4)

        return json.loads(jsonObj)

if __name__ == '__main__':

    # parser = argparse.ArgumentParser(description="Nmap automation tool")
    # parser.add_argument('sqlite')

    networkScanner = Network_Scanner()
    networkScanner.loadConfig()
    networkScanner.initializeSqlite()
    # scanData = networkScanner.nmapScan("target_files/ips_10.0_2019_07_18.txt")
    # print (scanData)
    
