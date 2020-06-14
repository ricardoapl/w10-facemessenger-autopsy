import os
import inspect
import csv

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


# Factory that defines the name and details of the module
# Allows Autopsy to create instances of the modules that will do the analysis
class W10FaceMessengerIngestModuleFactory(IngestModuleFactoryAdapter):

    moduleName = "W10-FaceMessenger @ Autopsy"

    def getModuleDisplayName(self):
        return self.moduleName

    def getModuleDescription(self):
        return "Data Source-level Ingest Module that wraps around W10-FaceMessenger."

    def getModuleVersionNumber(self):
        return "1.0"

    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return W10FaceMessengerIngestModule()


# Data Source-level Ingest Module (one gets created per data source)
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
        if not PlatformUtil.isWindowsOS():
            raise IngestModuleException("Not running on Windows")
        self.EXE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "w10-facemessenger.exe")
        if not os.path.exists(self.EXE_PATH):
            raise IngestModuleException("w10-facemessenger.exe was not found in module folder")
        # Create custom artifact attribute types
        self._startUpAttributeTypes()

    def _startUpAttributeTypes(self):
        # Custom attribute types for <<Contacts>>
        attributeName = "FB_ID"
        attributeValue = BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING
        attributeDisplayName = "Facebook ID"
        self.ATTRIBUTE_TYPE_FB_ID = self._createAttributeType(attributeName, attributeValue, attributeDisplayName)

        attributeName = "FB_PROFILE_PIC"
        attributeValue = BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING
        attributeDisplayName = "Profile Picture URL (Small)"
        self.ATTRIBUTE_TYPE_FB_PROFILE_PIC_SMALL = self._createAttributeType(attributeName, attributeValue, attributeDisplayName)

        attributeName = "FB_PROFILE_PIC_LARGE"
        attributeValue = BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING
        attributeDisplayName = "Profile Picture URL (Large)"
        self.ATTRIBUTE_TYPE_FB_PROFILE_PIC_LARGE = self._createAttributeType(attributeName, attributeValue, attributeDisplayName)

        # Custom attribute types for <<Messages>>
        attributeName = "FB_ID_FROM"
        attributeValue = BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING
        attributeDisplayName = "From Facebook ID"
        self.ATTRIBUTE_TYPE_FB_ID_FROM = self._createAttributeType(attributeName, attributeValue, attributeDisplayName)

        attributeName = "FB_NAME_FROM"
        attributeValue = BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING
        attributeDisplayName = "From Name"
        self.ATTRIBUTE_TYPE_FB_NAME_FROM = self._createAttributeType(attributeName, attributeValue, attributeDisplayName)

        attributeName = "FB_CONTENT_URL"
        attributeValue = BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING
        attributeDisplayName = "Content URL"
        self.ATTRIBUTE_TYPE_FB_URL_CONTENT = self._createAttributeType(attributeName, attributeValue, attributeDisplayName)

    # Wrapper method for org.sleuthkit.datamodel.Blackboard.getOrAddAttributeType
    # See http://sleuthkit.org/sleuthkit/docs/jni-docs/4.9.0/classorg_1_1sleuthkit_1_1datamodel_1_1_blackboard.html#a0b6ee76fbbdbab422a2d97fff0848dd7
    def _createAttributeType(self, typeName, valueType, displayName):
        blackboard = Case.getCurrentCase().getServices().getBlackboard()
        try:
            attributeType = blackboard.getOrAddAttributeType(typeName, valueType, displayName)
        except BlackboardException:
            self.log(Level.INFO, "There was a problem getting or adding the attribute type" + valueType)
        return attributeType

    # Where the analysis is done
    # The 'dataSource' object being passed in is of type org.sleuthkit.datamodel.Content
    # See http://www.sleuthkit.org/sleuthkit/docs/jni-docs/latest/interfaceorg_1_1sleuthkit_1_1datamodel_1_1_content.html
    # 'progressBar' is of type org.sleuthkit.autopsy.ingest.DataSourceIngestModuleProgress
    # See http://sleuthkit.org/autopsy/docs/api-docs/latest/classorg_1_1sleuthkit_1_1autopsy_1_1ingest_1_1_data_source_ingest_module_progress.html
    def process(self, dataSource, progressBar):
        progressBar.switchToIndeterminate()

        # Find Facebook Messenger (Beta) AppData
        fileManager = Case.getCurrentCase().getServices().getFileManager()
        directory = "Facebook.FacebookMessenger_8xx8rvfyw5nnt"
        parentDirectory = "AppData/Local/Packages"
        contents = fileManager.findFiles(dataSource, directory, parentDirectory)
    
        numContents = len(contents)
        progressBar.switchToDeterminate(numContents)
        contentCount = 0
        for content in contents:
            # Check if the user pressed cancel while we were busy
            if self.context.isJobCancelled():
                return IngestModule.ProcessResult.OK
            # Report work progress to end user
            contentCount += 1
            progressBar.progress(contentCount)
            self.log(Level.INFO, "Processing item {} of {}".format(contentCount, numContents))
            # Ignore false positives
            if not content.isDir():
                continue
            # XXX (ricardoapl) Where the (real) analysis happens
            self._process(content)

        # Once we are done, post a message to the ingest messages inbox
        messageType = IngestMessage.MessageType.DATA
        messageSource = W10FaceMessengerIngestModuleFactory.moduleName
        messageSubject = "Finished analysis! Please see the results tree."
        message = IngestMessage.createMessage(messageType, messageSource, messageSubject)
        IngestServices.getInstance().postMessage(message)
        return IngestModule.ProcessResult.OK
    
    # The 'content' object being passed in is of type org.sleuthkit.datamodel.Content
    # See http://www.sleuthkit.org/sleuthkit/docs/jni-docs/latest/interfaceorg_1_1sleuthkit_1_1datamodel_1_1_content.html
    # The 'content' object is assumed to be a Facebook Messenger (Beta) AppData directory with name 'Facebook.FacebookMessenger_8xx8rvfyw5nnt'
    def _process(self, content):
        caseTempDirectory = Case.getCurrentCase().getTempDirectory()
        dataSourceId = content.getDataSource().getId()
        parentPath = content.getParentPath()
        # Remove leading slash otherwise its considered an absolute path and all previous components are thrown away
        # See https://docs.python.org/3/library/os.path.html#os.path.join
        parentPath = parentPath.replace("/", "\\")[1:]
        contentName = content.getName()

        # Create temporary directory to extract content to
        tempPathToDataSource = os.path.join(caseTempDirectory, str(dataSourceId))
        tempPathToParent = os.path.join(tempPathToDataSource, parentPath)
        tempPathToContent = os.path.join(tempPathToParent, contentName)
        self.log(Level.INFO, "Creating temporary directory => " + tempPathToContent)
        os.makedirs(tempPathToContent)  # XXX (ricardoapl) Might want to wrap inside a try/except along with _extract()

        self._extract(content, tempPathToContent)
        self._analyze(content, tempPathToContent)

    # The 'content' object being passed in is of type org.sleuthkit.datamodel.Content
    # See http://www.sleuthkit.org/sleuthkit/docs/jni-docs/latest/interfaceorg_1_1sleuthkit_1_1datamodel_1_1_content.html
    def _extract(self, content, path):
        children = content.getChildren()
        for child in children:
            childName = child.getName()
            childPath = os.path.join(path, childName)
            if childName == "." or childName == "..":
                continue
            elif child.isFile():
                ContentUtils.writeToFile(child, File(childPath))
            elif child.isDir():
                os.mkdir(childPath)
                self._extract(child, childPath)

    # The 'content' object being passed in is of type org.sleuthkit.datamodel.Content
    # See http://www.sleuthkit.org/sleuthkit/docs/jni-docs/latest/interfaceorg_1_1sleuthkit_1_1datamodel_1_1_content.html
    # The 'content' object is assumed to be a Facebook Messenger (Beta) AppData directory with name 'Facebook.FacebookMessenger_8xx8rvfyw5nnt'
    def _analyze(self, content, path):
        # w10-facemessenger.exe must point to a user profile directory
        # 'path' should resemble '...\autopsy\cases\<Case>\Temp\<DataSourceId>\Users\<Username>\AppData\Local\Packages\Facebook.FacebookMessenger_8xx8rvfyw5nnt'
        # So we ought to remove '\AppData\Local\Packages\Facebook.FacebookMessenger_8xx8rvfyw5nnt' from it
        pathParts = path.split("\\")
        pathToUserProfile = "\\".join(pathParts[:-4])

        # We use ExecUtil because it will deal with the user cancelling the job
        self.log(Level.INFO, "Running => {} --input {} --output {} --format csv".format(self.EXE_PATH, pathToUserProfile, pathToUserProfile))
        cmd = ArrayList()
        cmd.add(self.EXE_PATH)
        cmd.add("--input")
        cmd.add(pathToUserProfile)
        cmd.add("--output")
        cmd.add(pathToUserProfile)
        cmd.add("--format")
        cmd.add("csv")
        # TODO (ricardoapl) Add CSV delimiter according to module settings (tell user he might get varying degrees of success)
        processBuilder = ProcessBuilder(cmd)
        ExecUtil.execute(processBuilder, DataSourceIngestModuleProcessTerminator(self.context))

        # If w10-facemessenger.exe was successful it should have generated a report directory
        pathToReport = os.path.join(pathToUserProfile, "report")
        self._populateBlackboard(content, pathToReport)

    # The 'content' object being passed in is of type org.sleuthkit.datamodel.Content
    # See http://www.sleuthkit.org/sleuthkit/docs/jni-docs/latest/interfaceorg_1_1sleuthkit_1_1datamodel_1_1_content.html
    # The 'content' object is assumed to be a Facebook Messenger (Beta) AppData directory with name 'Facebook.FacebookMessenger_8xx8rvfyw5nnt'
    def _populateBlackboard(self, content, path):
        self._populateBlackboardContacts(content, path)
        self._populateBlackboardMessages(content, path)
        self._populateBlackboardCachedImages(content, path)

    # The 'content' object being passed in is of type org.sleuthkit.datamodel.Content
    # See http://www.sleuthkit.org/sleuthkit/docs/jni-docs/latest/interfaceorg_1_1sleuthkit_1_1datamodel_1_1_content.html
    # The 'content' object is assumed to be a Facebook Messenger (Beta) AppData directory with name 'Facebook.FacebookMessenger_8xx8rvfyw5nnt'
    def _populateBlackboardContacts(self, content, path):
        pathToContactsCSV = os.path.join(path, "contacts.csv")
        if not os.path.exists(pathToContactsCSV):
            self.log(Level.INFO, "Unable to find contacts .csv report")
            return

        # We assume there exists a msys database from which the report was produced
        fileManager = Case.getCurrentCase().getServices().getFileManager()
        dataSource = content.getDataSource()
        fileName = "msys_%.db"
        dirName = os.path.join(content.getParentPath(), content.getName())
        contents = fileManager.findFiles(dataSource, fileName, dirName)
        if contents.isEmpty():
            self.log(Level.INFO, "Unable to find msys database")
            return
        # Expect a single match so retrieve the first (and only) file
        msysFile = contents.get(0)

        artifactTypeName = "FB_CONTACTS"
        artifactDisplayName = "Contacts"
        contactArtifactType = self._createArtifactType(artifactTypeName, artifactDisplayName)

        with open(pathToContactsCSV, "r") as csvfile:  # Python 2.x doesn't allow 'encoding' keyword argument
            contacts = csv.reader(csvfile)  # TODO (ricardoapl) Add CSV delimiter according to module settings
            isFirstEntry = True
            for contact in contacts:
                # We ignore the CSV header row (i.e. first row)
                if isFirstEntry:
                    isFirstEntry = False
                    continue
                self._addNewArtifactContact(msysFile, contact, contactArtifactType)
    
    # The 'content' object being passed in is of type org.sleuthkit.datamodel.Content
    # See http://www.sleuthkit.org/sleuthkit/docs/jni-docs/latest/interfaceorg_1_1sleuthkit_1_1datamodel_1_1_content.html
    # The 'content' object is assumed to be a Facebook Messenger (Beta) SQLite database file with name similar to 'msys_1234567890.db'
    def _addNewArtifactContact(self, content, contact, artifactType):
        source = W10FaceMessengerIngestModuleFactory.moduleName
        facebookId, picSmall, name, phone, email, picLarge = contact

        attributeFacebookId = BlackboardAttribute(self.ATTRIBUTE_TYPE_FB_ID, source, facebookId)
        attributeName = BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_NAME, source, name)
        attributePhone = BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PHONE_NUMBER, source, phone)
        attributeEmail = BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_EMAIL, source, email)
        attributePicSmall = BlackboardAttribute(self.ATTRIBUTE_TYPE_FB_PROFILE_PIC_SMALL, source, picSmall)
        attributePicLarge = BlackboardAttribute(self.ATTRIBUTE_TYPE_FB_PROFILE_PIC_LARGE, source, picLarge)

        artifact = content.newArtifact(artifactType.getTypeID())
        artifact.addAttribute(attributeFacebookId)
        artifact.addAttribute(attributeName)
        artifact.addAttribute(attributePhone)
        artifact.addAttribute(attributeEmail)
        artifact.addAttribute(attributePicSmall)
        artifact.addAttribute(attributePicLarge)
    
    # The 'content' object being passed in is of type org.sleuthkit.datamodel.Content
    # See http://www.sleuthkit.org/sleuthkit/docs/jni-docs/latest/interfaceorg_1_1sleuthkit_1_1datamodel_1_1_content.html
    # The 'content' object is assumed to be a Facebook Messenger (Beta) AppData directory with name 'Facebook.FacebookMessenger_8xx8rvfyw5nnt'
    def _populateBlackboardMessages(self, content, path):
        pathToThreads = os.path.join(path, "messages")
        threads = os.listdir(pathToThreads)
        if not threads:
            self.log(Level.INFO, "Unable to find messages .csv report(s)")
            return

        # We assume there exists a msys database from which the report was produced
        fileManager = Case.getCurrentCase().getServices().getFileManager()
        dataSource = content.getDataSource()
        fileName = "msys_%.db"
        dirName = os.path.join(content.getParentPath(), content.getName())
        contents = fileManager.findFiles(dataSource, fileName, dirName)
        if contents.isEmpty():
            self.log(Level.INFO, "Unable to find msys database")
            return
        # Expect a single match so retrieve the first (and only) file
        msysFile = contents.get(0)
        
        artifactTypeName = "FB_MESSAGES"
        artifactDisplayName = "Messages"
        messageArtifactType = self._createArtifactType(artifactTypeName, artifactDisplayName)

        for thread in threads:
            pathToMessagesCSV = os.path.join(pathToThreads, thread)
            with open(pathToMessagesCSV, "r") as csvfile:
                messages = csv.reader(csvfile)  # TODO (ricardoapl) Add CSV delimiter according to module settings
                isFirstEntry = True
                for message in messages:
                    # We ignore the CSV header row (i.e. first row)
                    if isFirstEntry:
                        isFirstEntry = False
                        continue
                    self._addNewArtifactMessage(msysFile, message, messageArtifactType)

    # The 'content' object being passed in is of type org.sleuthkit.datamodel.Content
    # See http://www.sleuthkit.org/sleuthkit/docs/jni-docs/latest/interfaceorg_1_1sleuthkit_1_1datamodel_1_1_content.html
    # The 'content' object is assumed to be a Facebook Messenger (Beta) SQLite database file with name similar to 'msys_1234567890.db'
    def _addNewArtifactMessage(self, content, message, artifactType):
        source = W10FaceMessengerIngestModuleFactory.moduleName
        senderId = message[2]
        senderName = message[3]
        # TODO (ricardoapl) dateTime = message[1]
        text = message[4]
        playableURL = message[6]

        attributeSenderId = BlackboardAttribute(self.ATTRIBUTE_TYPE_FB_ID_FROM, source, senderId)
        attributeSenderName = BlackboardAttribute(self.ATTRIBUTE_TYPE_FB_NAME_FROM, source, senderName)
        # TODO (ricardoapl) attributeDateTime = BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME, source, dateTime)
        attributeText = BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_TEXT, source, text)
        attributeContentURL = BlackboardAttribute(self.ATTRIBUTE_TYPE_FB_URL_CONTENT, source, playableURL)

        artifact = content.newArtifact(artifactType.getTypeID())
        artifact.addAttribute(attributeSenderId)
        artifact.addAttribute(attributeSenderName)
        # TODO (ricardoapl) artifact.addAttribute(attributeDateTime)
        artifact.addAttribute(attributeText)
        artifact.addAttribute(attributeContentURL)
    
    # The 'content' object being passed in is of type org.sleuthkit.datamodel.Content
    # See http://www.sleuthkit.org/sleuthkit/docs/jni-docs/latest/interfaceorg_1_1sleuthkit_1_1datamodel_1_1_content.html
    # The 'content' object is assumed to be a Facebook Messenger (Beta) AppData directory with name 'Facebook.FacebookMessenger_8xx8rvfyw5nnt'
    def _populateBlackboardCachedImages(self, content, path):
        pathToCachedImagesCSV = os.path.join(path, "report_images.csv")
        if not os.path.exists(pathToCachedImagesCSV):
            self.log(Level.INFO, "Unable to find cached images .csv report")
            return

        artifactTypeName = "FB_CACHED_IMAGES"
        artifactDisplayName = "Cached Images (hindsight.exe)"
        cachedImageArtifactType = self._createArtifactType(artifactTypeName, artifactDisplayName)

        with open(pathToCachedImagesCSV, "r") as csvfile:  # Python 2.x doesn't allow 'encoding' keyword argument
            images = csv.reader(csvfile)  # TODO (ricardoapl) Add CSV delimiter according to module settings
            isFirstEntry = True
            for image in images:
                # We ignore the CSV header row (i.e. first row)
                if isFirstEntry:
                    isFirstEntry = False
                    continue
                sourceContent = self._searchSourceContent(content, image)
                self._addNewArtifactCachedImage(sourceContent, image, cachedImageArtifactType)

    # The 'content' object being passed in is of type org.sleuthkit.datamodel.Content
    # See http://www.sleuthkit.org/sleuthkit/docs/jni-docs/latest/interfaceorg_1_1sleuthkit_1_1datamodel_1_1_content.html
    # The 'content' object is assumed to be a Facebook Messenger (Beta) AppData directory with name 'Facebook.FacebookMessenger_8xx8rvfyw5nnt'
    def _searchSourceContent(self, content, csvrow):
        location, origin, timestamp, url = csvrow
        
        # 'location' should resemble '...\Temp\<DataSourceId>\<Username>\AppData\Local\Packages\Facebook.FacebookMessenger_8xx8rvfyw5nnt\LocalState\Partitions\8bda49db...'
        # We just want to keep what's after <DataSourceId>
        locationParts = location.split("\\")
        sourceLocation = "\\".join(locationParts[-8:])

        dirName = os.path.join(sourceLocation, "Cache")
        # Autopsy expects forward slashes ('/') in paths, so we have to replace any occurance of backward slashes ('\\')
        dirName = dirName.replace("\\", "/")

        # 'origin' should resemble '<filename> [<offset>]'
        # We just want <filename> (not the <offset>)
        fileName = origin.split(" ")[0]

        fileManager = Case.getCurrentCase().getServices().getFileManager()
        dataSource = content.getDataSource()
        contents = fileManager.findFiles(dataSource, fileName, dirName)
        if contents.isEmpty():
            self.log(Level.INFO, "Unable to find source of cached image")
            # TODO (ricardoapl) We should return something appropriate (or raise an exception)
            return
        # Expect a single match so retrieve the first (and only) file
        sourceContent = contents.get(0)
        return sourceContent

    # The 'content' object being passed in is of type org.sleuthkit.datamodel.Content
    # See http://www.sleuthkit.org/sleuthkit/docs/jni-docs/latest/interfaceorg_1_1sleuthkit_1_1datamodel_1_1_content.html
    def _addNewArtifactCachedImage(self, content, image, artifactType):
        source = W10FaceMessengerIngestModuleFactory.moduleName
        location, origin, timestamp, url = image  # XXX (ricardoapl) Unpacking the whole list seems overkill

        attributeUrl = BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_URL, source, url)

        artifact = content.newArtifact(artifactType.getTypeID())
        artifact.addAttribute(attributeUrl)

    # Wrapper method for org.sleuthkit.datamodel.Blackboard.getOrAddArtifactType
    # See http://sleuthkit.org/sleuthkit/docs/jni-docs/4.9.0/classorg_1_1sleuthkit_1_1datamodel_1_1_blackboard.html#ab1d9c5b4bf7662e80a112b5786d1cdc6
    def _createArtifactType(self, typeName, displayName):
        blackboard = Case.getCurrentCase().getServices().getBlackboard()
        try:
            artifactType = blackboard.getOrAddArtifactType(typeName, "Messenger (Beta) " + displayName)
        except BlackboardException:
            self.log(Level.INFO, "There was a problem getting or adding the artifact type" + typeName)
        return artifactType
