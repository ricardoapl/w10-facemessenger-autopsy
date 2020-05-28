import os
import jarray
import inspect

import java.util.ArrayList as ArrayList
from java.io import File
from java.lang import Class
from java.lang import System
from java.lang import ProcessBuilder
from java.util.logging import Level
from org.sleuthkit.datamodel import SleuthkitCase
from org.sleuthkit.datamodel import AbstractFile
from org.sleuthkit.datamodel import ReadContentInputStream
from org.sleuthkit.datamodel import BlackboardArtifact
from org.sleuthkit.datamodel import BlackboardAttribute
from org.sleuthkit.datamodel import Image
from org.sleuthkit.autopsy.ingest import IngestModule
from org.sleuthkit.autopsy.ingest import IngestJobContext
from org.sleuthkit.autopsy.ingest.IngestModule import IngestModuleException
from org.sleuthkit.autopsy.ingest import DataSourceIngestModule
from org.sleuthkit.autopsy.ingest import DataSourceIngestModuleProcessTerminator
from org.sleuthkit.autopsy.ingest import FileIngestModule
from org.sleuthkit.autopsy.ingest import IngestModuleFactoryAdapter
from org.sleuthkit.autopsy.ingest import IngestMessage
from org.sleuthkit.autopsy.ingest import IngestServices
from org.sleuthkit.autopsy.coreutils import PlatformUtil
from org.sleuthkit.autopsy.coreutils import Logger
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.casemodule.services import Services
from org.sleuthkit.autopsy.casemodule.services import FileManager
from org.sleuthkit.autopsy.casemodule.services import Blackboard


# Factory that defines the name and details of the module and allows Autopsy
# to create instances of the modules that will do the analysis.
class FBMessengerIngestModuleFactory(IngestModuleFactoryAdapter):

    moduleName = "FBMessenger Data Source Module"

    def getModuleDisplayName(self):
        return self.moduleName

    def getModuleDescription(self):
        return "Extract artifacts produced by Facebook Messenger (Beta)."

    def getModuleVersionNumber(self):
        return "1.0"

    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return FBMessengerIngestModule()


# Data Source-level ingest module.  One gets created per data source.
class FBMessengerIngestModule(DataSourceIngestModule):

    _logger = Logger.getLogger(FBMessengerIngestModuleFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    def __init__(self):
        self.context = None

    # Where any setup and configuration is done
    # 'context' is an instance of org.sleuthkit.autopsy.ingest.IngestJobContext.
    # See: http://sleuthkit.org/autopsy/docs/api-docs/latest/classorg_1_1sleuthkit_1_1autopsy_1_1ingest_1_1_ingest_job_context.html
    def startUp(self, context):
        self.context = context
    
        # Get path to FBMessenger based on where this script is run from.
        # Assumes FBMessenger is in same folder as script
        # Verify it is there before any ingest starts
        fbmessenger_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), r"fbmessenger\__main__.py")
        self.path_to_fbmessenger = File(fbmessenger_path)
        if not self.path_to_fbmessenger.exists():
            raise IngestModuleException("FBMessenger was not found in the module folder")

    # Where the analysis is done.
    # The 'dataSource' object being passed in is of type org.sleuthkit.datamodel.Content.
    # See: http://www.sleuthkit.org/sleuthkit/docs/jni-docs/latest/interfaceorg_1_1sleuthkit_1_1datamodel_1_1_content.html
    # 'progressBar' is of type org.sleuthkit.autopsy.ingest.DataSourceIngestModuleProgress
    # See: http://sleuthkit.org/autopsy/docs/api-docs/latest/classorg_1_1sleuthkit_1_1autopsy_1_1ingest_1_1_data_source_ingest_module_progress.html
    def process(self, dataSource, progressBar):

        # we don't know how much work there is yet
        progressBar.switchToIndeterminate()

        # We make use of hindsight Windows EXE, so bail if we aren't on Windows
        if not PlatformUtil.isWindowsOS(): 
            self.log(Level.INFO, "Ignoring data source. Not running on Windows")
            return IngestModule.ProcessResult.OK

        # Verify we have a disk image and not a folder of files
        if not isinstance(dataSource, Image):
            self.log(Level.INFO, "Ignoring data source.  Not an image")
            return IngestModule.ProcessResult.OK

        imagePaths = dataSource.getPaths()

        # TODO (ricardoapl) Add arguments for HTML report
        # Run the FBMessenger, saving output to reportFile
        # We use ExecUtil because it will deal with the user cancelling the job
        self.log(Level.INFO, "Running FBMessenger on data source")
        cmd = ArrayList()
        cmd.add(self.path_to_fbmessenger.toString())
        # Add each argument in its own line. I.e. "-f foo" would be two calls to .add()
        cmd.add(imagePaths[0])
        
        processBuilder = ProcessBuilder(cmd)
        processBuilder.redirectOutput(reportFile)
        ExecUtil.execute(processBuilder, DataSourceIngestModuleProcessTerminator(self.context))

        # TODO (ricardoapl) Move FBMessenger resulting files to case report dir
        # Add the report to the case, so it shows up in the tree
        # Do not add report to the case tree if the ingest is cancelled before finish.
        if not self.context.dataSourceIngestIsCancelled():
            Case.getCurrentCase().addReport(reportFile.toString(), "Run EXE", "img_stat output")
        else:
            if reportFile.exists():
                if not reportFile.delete():
                    self.log(LEVEL.warning,"Error deleting the incomplete report file")

        return IngestModule.ProcessResult.OK