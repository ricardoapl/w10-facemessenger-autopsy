import os

from java.lang import System
from java.util.logging import Level
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.coreutils import Logger
from org.sleuthkit.autopsy.report import GeneralReportModuleAdapter
from org.sleuthkit.autopsy.report.ReportProgressPanel import ReportStatus


# TODO: Rename the class to something more specific
class SampleGeneralReportModule(GeneralReportModuleAdapter):

    # TODO: Rename this.  Will be shown to users when making a report
    moduleName = "Sample Report Module"

    _logger = None
    def log(self, level, msg):
        if _logger == None:
            _logger = Logger.getLogger(self.moduleName)

        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    def getName(self):
        return self.moduleName

    # TODO: Give it a useful description
    def getDescription(self):
        return "A sample Jython report module"

    # TODO: Update this to reflect where the report file will be written to
    def getRelativeFilePath(self):
        return "sampleReport.txt"

    # TODO: Update this method to make a report
    # The 'baseReportDir' object being passed in is a string with the directory that reports are being stored in.   Report should go into baseReportDir + getRelativeFilePath().
    # The 'progressBar' object is of type ReportProgressPanel.
    #   See: http://sleuthkit.org/autopsy/docs/api-docs/latest/classorg_1_1sleuthkit_1_1autopsy_1_1report_1_1_report_progress_panel.html
    def generateReport(self, baseReportDir, progressBar):

        # For an example, we write a file with the number of files created in the past 2 weeks
        # Configure progress bar for 2 tasks
        progressBar.setIndeterminate(False)
        progressBar.start()
        progressBar.setMaximumProgress(2)

        # Find epoch time of when 2 weeks ago was
        currentTime = System.currentTimeMillis() / 1000
        minTime = currentTime - (14 * 24 * 60 * 60) # (days * hours * minutes * seconds)

        # Query the database for files that meet our criteria
        sleuthkitCase = Case.getCurrentCase().getSleuthkitCase()
        files = sleuthkitCase.findAllFilesWhere("crtime > %d" % minTime)

        fileCount = 0
        for file in files:
            fileCount += 1
            # Could do something else here and write it to HTML, CSV, etc.

        # Increment since we are done with step #1
        progressBar.increment()

        # Write the count to the report file.
        fileName = os.path.join(baseReportDir, self.getRelativeFilePath())
        report = open(fileName, 'w')
        report.write("file count = %d" % fileCount)
        report.close()

        # Add the report to the Case, so it is shown in the tree
        Case.getCurrentCase().addReport(fileName, self.moduleName, "File Count Report")

        progressBar.increment()

        # Call this with ERROR if report was not generated
        progressBar.complete(ReportStatus.COMPLETE)