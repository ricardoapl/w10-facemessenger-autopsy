import os
import inspect

import java.util.ArrayList as ArrayList
from java.io import File
from java.lang import System
from java.lang import ProcessBuilder
from java.util.logging import Level
from org.sleuthkit.datamodel import SleuthkitCase
from org.sleuthkit.datamodel import AbstractFile
from org.sleuthkit.datamodel import ReadContentInputStream
from org.sleuthkit.datamodel import BlackboardArtifact
from org.sleuthkit.datamodel import BlackboardAttribute
from org.sleuthkit.autopsy.ingest import IngestModule
from org.sleuthkit.autopsy.ingest import IngestJobContext
from org.sleuthkit.autopsy.ingest.IngestModule import IngestModuleException
from org.sleuthkit.autopsy.ingest import DataSourceIngestModule
from org.sleuthkit.autopsy.ingest import DataSourceIngestModuleProcessTerminator
from org.sleuthkit.autopsy.ingest import IngestModuleFactoryAdapter
from org.sleuthkit.autopsy.ingest import IngestMessage
from org.sleuthkit.autopsy.ingest import IngestServices
from org.sleuthkit.autopsy.coreutils import PlatformUtil
from org.sleuthkit.autopsy.coreutils import Logger
from org.sleuthkit.autopsy.coreutils import ExecUtil
from org.sleuthkit.autopsy.datamodel import ContentUtils
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.casemodule.services import Services
from org.sleuthkit.autopsy.casemodule.services import FileManager
from org.sleuthkit.autopsy.casemodule.services import Blackboard


class W10FaceMessengerIngestModuleFactory(IngestModuleFactoryAdapter):

    moduleName = "W10-FaceMessenger @ Autopsy"

    def getModuleDisplayName(self):
        return self.moduleName

    def getModuleDescription(self):
        return "Wrapper module for W10-FaceMessenger."

    def getModuleVersionNumber(self):
        return "1.0"

    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return W10FaceMessengerIngestModule()


class W10FaceMessengerIngestModule(DataSourceIngestModule):

    _logger = Logger.getLogger(W10FaceMessengerIngestModuleFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    def __init__(self):
        self.context = None

    # Where any setup and configuration is done
    # 'context' is an instance of org.sleuthkit.autopsy.ingest.IngestJobContext
    # See http://sleuthkit.org/autopsy/docs/api-docs/latest/classorg_1_1sleuthkit_1_1autopsy_1_1ingest_1_1_ingest_job_context.html
    def startUp(self, context):
        self.context = context
        self.pathToEXE = os.path.join(os.path.dirname(os.path.abspath(__file__)), r"w10-facemessenger\w10-facemessenger.exe")
        if not os.path.exists(self.pathToEXE):
            raise IngestModuleException("W10-FaceMessenger was not found in module folder")

    # Where the analysis is done
    # The 'dataSource' object being passed in is of type org.sleuthkit.datamodel.Content
    # See http://www.sleuthkit.org/sleuthkit/docs/jni-docs/latest/interfaceorg_1_1sleuthkit_1_1datamodel_1_1_content.html
    # 'progressBar' is of type org.sleuthkit.autopsy.ingest.DataSourceIngestModuleProgress
    # See http://sleuthkit.org/autopsy/docs/api-docs/latest/classorg_1_1sleuthkit_1_1autopsy_1_1ingest_1_1_data_source_ingest_module_progress.html
    def process(self, dataSource, progressBar):

        if not PlatformUtil.isWindowsOS(): 
            self.log(Level.INFO, "Ignoring data source. Not running on Windows")
            return IngestModule.ProcessResult.OK

        progressBar.switchToIndeterminate()
        
        # Find user profile parent directories (%SystemDrive%\Users)
        fileManager = Case.getCurrentCase().getServices().getFileManager()
        directories = fileManager.findFiles(dataSource, "Users")

        numDirectories = len(directories)
        progressBar.switchToDeterminate(numDirectories)
        directoryCount = 0
        for directory in directories:

            # Check if the user pressed cancel while we were busy
            if self.context.isJobCancelled():
                return IngestModule.ProcessResult.OK
            
            # Report work progress to end user
            directoryCount += 1
            progressBar.progress(directoryCount)
            self.log(Level.INFO, "Processing directory {} of {}".format(directoryCount, numDirectories))
            
            # Ignore false positives
            if not directory.isDir():
                continue

            # Where the (real) analysis happens
            self._processContent(directory)
            
        # Once we are done, post a message to the ingest messages inbox
        messageType = IngestMessage.MessageType.DATA
        messageSource = W10FaceMessengerIngestModuleFactory.moduleName
        messageSubject = "Finished analysis! Please see <<Reports>>"
        message = IngestMessage.createMessage(messageType, messageSource, messageSubject)
        IngestServices.getInstance().postMessage(message)
        return IngestModule.ProcessResult.OK

    def _processContent(self, directory):
        
        # Create temporary directory to extract content to
        caseTempDirectory = Case.getCurrentCase().getTempDirectory()
        tempDirectoryName = str(directory.getId())
        tempDirectory = os.path.join(caseTempDirectory, tempDirectoryName)
        
        self.log(Level.INFO, "Creating temporary directory " + tempDirectory)
        os.mkdir(tempDirectory)

        self._extractContent(directory, tempDirectory)
        self._analyzeContent(tempDirectory)

    # Extract data from Autopsy into filesystem for later analysis
    # The 'content' object being passed in is of type org.sleuthkit.datamodel.Content
    # See http://sleuthkit.org/sleuthkit/docs/jni-docs/4.9.0//classorg_1_1sleuthkit_1_1datamodel_1_1_abstract_content.html
    def _extractContent(self, content, path):
        children = content.getChildren()
        for child in children:
            childName = child.getName()
            if childName == "." or childName == "..":
                continue
            elif child.isFile():
                childPath = os.path.join(path, childName)
                ContentUtils.writeToFile(child, File(childPath))
            elif child.isDir():
                childPath = os.path.join(path, childName)
                os.mkdir(childPath)
                self._extractContent(child, childPath)

    # XXX (ricardoapl) We assume that path has been previously populated with user profile directories
    def _analyzeContent(self, path):

        # Ignore false positives
        profiles = [directory for directory in os.listdir(path) if os.path.isdir(os.path.join(path, directory))]
        
        for profile in profiles:

            caseReportDirectory = Case.getCurrentCase().getReportDirectory()
            reportDirectoryName = os.path.basename(path) + "-" + profile
            reportDirectory = os.path.join(caseReportDirectory, reportDirectoryName)
            os.mkdir(reportDirectory)
            profileDirectory = os.path.join(path, profile)

            # Run the W10-FaceMessenger EXE, saving output to reportDirectory
            # We use ExecUtil because it will deal with the user cancelling the job
            self.log(Level.INFO, "Running W10-FaceMessenger on profile " + reportDirectoryName)
            cmd = ArrayList()
            cmd.add(self.pathToEXE)
            cmd.add("--input")
            cmd.add(profileDirectory)
            cmd.add("--output")
            cmd.add(reportDirectory)
            
            # TODO (ricardoapl) Add depth argument according to module settings

            processBuilder = ProcessBuilder(cmd)
            ExecUtil.execute(processBuilder, DataSourceIngestModuleProcessTerminator(self.context))
            
            # TODO (ricardoapl) Remove directories for which no report was produced

            # Add the report to the case, so it shows up in the tree
            # Do not add report to the case tree if the ingest is cancelled before finish
            if not self.context.dataSourceIngestIsCancelled():
                reportFileName = os.path.join(reportDirectory, "report\\report.html")
                reportModuleName = W10FaceMessengerIngestModuleFactory.moduleName
                reportName = "W10-FaceMessenger " + reportDirectoryName
                Case.getCurrentCase().addReport(reportFileName, reportModuleName, reportName)
            else:
                reportFile = File(reportFileName)
                if reportFile.exists():
                    if not reportFile.delete():
                        self.log(LEVEL.warning, "Error deleting the incomplete report file")