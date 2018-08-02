import sys
import os
import csv
import logging
from PyQt5 import QtCore, QtGui
from PyQt5.QtWidgets import QApplication, QDialog
from PyQt5.uic import loadUi


#TODO:
# @001 process interrupt: Abort and user_exit_GUI
# @002 Fix logging | display
# @003 'Retain Logs' - delete

class MainWindow(QDialog):
    def __init__(self, parentDir):
        super(MainWindow, self).__init__()
        loadUi(str(parentdir+'\GUIv'+str(guiVer)+'.ui'), self)
        self.setWindowTitle('Ingest Indexer v'+str(version))
        self.logViewer.setVerticalScrollBarPolicy(2)  # Always Visible - Enables autoscroll
        #Declaration
        self.progress = 0
        self.log = displayText
        # self.logViewer.setText(displayText)
        self.progressIncrement = int
        self.masterParse = [['Hardware', 'IP', 'Port']]
        self.masterIndex = [['Hardware', 'IP', 'Port', 'SourceID', 'SourceName']]
        self.sources = []
        self.sourceAnalysis = []
        #Variables
        self.version = version
        self.lineEditInput.setText(parentdir + '\Input\\')
        self.lineEditOutput.setText(parentdir+'\\')
        #Connections
        self.pushButton.clicked.connect(self.user_execution)

    @property
    def configCount(self):
        return len([name for name in os.listdir(self.lineEditInput.text())])

    @property
    def verbose(self):
        return True if self.checkBox.checkState() == 2 else False

    def user_execution(self):
        self.setupEnv()
        logging.info('Processing '+str(self.configCount)+' files.')
        self.progressIncrement = 10 / sum(1 for log in os.listdir(self.lineEditInput.text())) # Refactor Progress Increments
        for inputfile in os.listdir(self.lineEditInput.text()):  # For each file in InputDir, parse & save current ver
            inputfile = inputfile.replace(".csv", "")
            datatype = ''.join([i for i in inputfile if not i.isdigit()]).upper()  # Sterilize filename for datatype
            logging.info("Begining parse of " + str(inputfile).upper())
            self.Parser(datatype, inputfile)
            logging.info("Completed parse of " + str(inputfile).upper())
        logging.info("Beginning Indexing.")
        self.Index()
        logging.info("Indexing completed.")
        self.printLog()

    def Parser(self, datatype, file):
        # Variables
        inputConfig = self.lineEditInput.text() + '\\' + file + ".csv"

        if datatype == "DCM":  # If DCM datatype, import as CSV and iterate by line
            csv.register_dialect('semicolon', delimiter=';')
            with open(inputConfig, "r") as dataset:
                inputdata = csv.reader(dataset, dialect='semicolon')
                for log in inputdata:
                    if len(log) != 22:  # Is line formatted as log entry?
                        pass
                    else:
                        if log[17] == "eStreamingSetting_Auto" or log[17] == "eStreamingSetting_On":  # Is push enabled?
                            pushconfig = [file.upper(), log[14], log[15]]
                            self.masterParse.append(pushconfig)
                            logging.debug("Parsed:" + str(log[20]).strip() + " | " + str(log[14]).strip() + ":" + str(log[15]).strip())
                        else:
                            pass


        elif datatype == "LB":
            print("Datatype: " + datatype)
        elif datatype == "ILB":
            print("Datatype: " + datatype)
        elif datatype == "SLB":
            print("Datatype: " + datatype)
        elif datatype == "ZIXI":
            print("Datatype: " + datatype)
        else:
            logging.critical("Error: Datatype \"" + datatype + "\" not defined")
        self.incrementProg()

    def Index(self):
        # Declaration
        sourceNameIndex = {}
        datasetlen = sum(1 for log in self.masterParse)  # Used for StatusUpdate during processing
        self.progressIncrement = 60 / datasetlen  # Refactor Progress Increments
        totalLogs = datasetlen

        # Variables
        sourceAnalysisdir = parentdir + "\CVRData\SourceAnalysis.csv"
        sourcesdir = parentdir + "\CVRData\Sources.csv"
        indexerOutput = self.lineEditOutput.text() + "\Index.csv"

        #Import CVR Configs
        self.loadFile(sourcesdir, self.sources)
        self.loadFile(sourceAnalysisdir, self.sourceAnalysis)

        for line in self.sourceAnalysis:  # Populate sourceNameIndex
            if line[0] != 'SourceName': sourceNameIndex[line[2]] = line[0]

        for outputConfig in self.masterParse:
            sourcesToIP = []
            sourcesToPort = []

            for line in self.sourceAnalysis:  # Generate array of sources to same IP
                if line[3] == outputConfig[1]:
                    sourcesToIP.append(line[2])
            for line in self.sources:  # Generate array of sources using same Port
                if line[4] == outputConfig[2]:
                    sourcesToPort.append(line[6])
            for testSourceID in sourcesToPort:  # Compare sourcesToPort and sourcesToIP, return matching SourceID
                if testSourceID in sourcesToIP:
                    matchedsource = outputConfig
                    matchedsource.append(testSourceID)  # Add to input array
                    self.masterIndex.append(matchedsource)  # output indexed array

            # Populate sourceNameIndex
            sourceNameIndex[line[2]] = line[0]

            # StatusUpdate
            datasetlen -= 1
            # Debugging
            logging.debug('Indexed:'+str(outputConfig))
            self.incrementProg()

        # Add CVR Sourcenames to index
        for indexedSource in self.masterIndex:
            indexedSource.append(sourceNameIndex.get(indexedSource[3]))

        # Debugging
        outputLen = len(self.masterIndex)
        logging.info('Indexed '+str(outputLen)+' routes from '+str(totalLogs)+' pushes.')
        self.printLog()

        # Output
        self.progressIncrement = 30 / outputLen  # Refactor Progress Increments
        logging.debug('Final Index')
        with open(indexerOutput, 'w', newline='') as f:
            writer = csv.writer(f, dialect='excel')
            for log in self.masterIndex:
                logging.debug('Output:' + str(log))
                self.printLog()
                writer.writerow(log)
                self.incrementProg()
            logging.info('Outputting completed Index to: '+indexerOutput)
            self.printLog()
        self.progress = 100
        self.printLog()

    def incrementProg(self):
        self.progress = self.progress + self.progressIncrement
        self.printLog()

    def printLog(self):
        # self.logViewer.setText(self.log)
        self.logViewer.moveCursor(QtGui.QTextCursor.End)
        self.progressBar.setValue(self.progress)
        self.logViewer.moveCursor(QtGui.QTextCursor.End)
        self.logViewer.ensureCursorVisible()
        QtCore.QCoreApplication.processEvents()
        # if QApplication.exit(0) == 0: sys.exit(0) #@001

    def logHeader(self):
        logging.debug('---INIT---')
        logging.debug('Version: ' + str(self.version))
        logging.debug('Verbose: ' + str(self.verbose))
        logging.debug('Input Dir: ' + str(self.lineEditInput.text()))
        logging.debug('Output Dir: ' + str(self.lineEditOutput.text()))
        logging.debug('---Execute---')

    def loadFile(self, filename, output):
        with open(filename, "r") as f: #populate sourceNameIndex seperately due to iteration bug
            input = csv.reader(f, dialect='excel')
            for line in input:  # Populate sourceNameIndex
                output.append(line)

    def setupEnv(self):
        logging.basicConfig(format='%(levelname)s:%(asctime)s:%(message)s', filename='log.log', level=logging.DEBUG, datefmt='%m/%d/%Y %H%M%S')
        self.progress = 0
        self.progressBar.setValue(0)
        self.logHeader()
        self.printLog()

#GlobalVariables
displayText = "To use this tool, simply complete the following setup:\n" \
              "    -Place all raw DCM config files in CSV format in the input directory, following correct naming convention (ex. DCM01.csv)\n" \
              "    -Ensure the CVR Sources.csv and SourceAnalysis.csv files are up to date (\CVRData\)\n" \
              "(Please note that verbose logging will result in slower processing)"
parentdir = os.path.dirname(os.path.realpath(__file__))
version = 0.22
guiVer = 3

app = QApplication(sys.argv)
GUI = MainWindow(parentdir)
GUI.show()#@001
sys.exit(app.exec_())