import os
import inspect
import csv
import datetime
import calendar
from collections import defaultdict

from java.io import File
from java.lang import ProcessBuilder
from java.util import ArrayList
from java.util.logging import Level
from org.sleuthkit.datamodel import BlackboardAttribute
from org.sleuthkit.datamodel import Account
from org.sleuthkit.datamodel.blackboardutils import CommunicationArtifactsHelper
from org.sleuthkit.datamodel.blackboardutils.CommunicationArtifactsHelper import CommunicationDirection
from org.sleuthkit.datamodel.blackboardutils.CommunicationArtifactsHelper import MessageReadStatus
from org.sleuthkit.datamodel.blackboardutils.attributes import MessageAttachments
from org.sleuthkit.datamodel.blackboardutils.attributes.MessageAttachments import URLAttachment
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
        self._startUpAttributeTypes()
        self._startUpArtifactTypes()

    def _startUpAttributeTypes(self):
        attributeName = "FB_PROFILE_PIC"
        attributeValue = BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING
        attributeDisplayName = "Profile Picture URL"
        self.ATTRIBUTE_TYPE_FB_PROFILE_PIC = self._createAttributeType(attributeName, attributeValue, attributeDisplayName)

        attributeName = "FB_USER_ID_FROM"
        attributeValue = BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING
        attributeDisplayName = "From User ID"
        self.ATTRIBUTE_TYPE_FB_USER_ID_FROM = self._createAttributeType(attributeName, attributeValue, attributeDisplayName)

        attributeName = "FB_DISPLAY_NAME_FROM"
        attributeValue = BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING
        attributeDisplayName = "From Display Name"
        self.ATTRIBUTE_TYPE_FB_DISPLAY_NAME_FROM = self._createAttributeType(attributeName, attributeValue, attributeDisplayName)

        attributeName = "FB_ATTACHMENT_URL"
        attributeValue = BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING
        attributeDisplayName = "Attachment URL"
        self.ATTRIBUTE_TYPE_FB_URL_CONTENT = self._createAttributeType(attributeName, attributeValue, attributeDisplayName)

    # Wrapper method for org.sleuthkit.datamodel.Blackboard.getOrAddAttributeType
    # See http://sleuthkit.org/sleuthkit/docs/jni-docs/4.9.0/classorg_1_1sleuthkit_1_1datamodel_1_1_blackboard.html#a0b6ee76fbbdbab422a2d97fff0848dd7
    def _createAttributeType(self, typeName, valueType, displayName):
        blackboard = Case.getCurrentCase().getServices().getBlackboard()
        try:
            attributeType = blackboard.getOrAddAttributeType(typeName, valueType, displayName)
        except BlackboardException:
            self.log(Level.INFO, "There was a problem getting or adding the attribute type " + valueType)
        return attributeType

    def _startUpArtifactTypes(self):
        artifactTypeName = "FB_CONTACT"
        artifactDisplayName = "Contacts"
        self.ARTIFACT_TYPE_FB_CONTACT = self._createArtifactType(artifactTypeName, artifactDisplayName)

        artifactTypeName = "FB_MESSAGE"
        artifactDisplayName = "Messages"
        self.ARTIFACT_TYPE_FB_MESSAGE = self._createArtifactType(artifactTypeName, artifactDisplayName)

        artifactTypeName = "FB_CACHED_IMAGE"
        artifactDisplayName = "Cached Images"
        self.ARTIFACT_TYPE_FB_CACHED_IMAGE = self._createArtifactType(artifactTypeName, artifactDisplayName)

        artifactTypeName = "FB_LOST_FOUND"
        artifactDisplayName = "Deleted Database Records"
        self.ARTIFACT_TYPE_FB_LOST_FOUND = self._createArtifactType(artifactTypeName, artifactDisplayName)

    # Wrapper method for org.sleuthkit.datamodel.Blackboard.getOrAddArtifactType
    # See http://sleuthkit.org/sleuthkit/docs/jni-docs/4.9.0/classorg_1_1sleuthkit_1_1datamodel_1_1_blackboard.html#ab1d9c5b4bf7662e80a112b5786d1cdc6
    def _createArtifactType(self, typeName, displayName):
        blackboard = Case.getCurrentCase().getServices().getBlackboard()
        try:
            artifactType = blackboard.getOrAddArtifactType(typeName, "Messenger (Beta) " + displayName)
        except BlackboardException:
            self.log(Level.INFO, "There was a problem getting or adding the artifact type " + typeName)
        return artifactType

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
            # Report progress to end user
            contentCount += 1
            progressBar.progress(contentCount)
            self.log(Level.INFO, "Processing item {} of {}".format(contentCount, numContents))
            # Ignore false positives
            if not content.isDir():
                continue
            # Where the REAL analysis happens
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
        # TODO (ricardoapl) Add CSV delimiter ('~', '^')
        processBuilder = ProcessBuilder(cmd)
        ExecUtil.execute(processBuilder, DataSourceIngestModuleProcessTerminator(self.context))

        # If w10-facemessenger.exe was successful it should have generated a report directory
        pathToReport = os.path.join(pathToUserProfile, "report")
        self._analyzeCachedImages(content, pathToReport)
        self._analyzeLostFound(content, pathToReport)
        self._analyzeContacts(content, pathToReport)
        self._analyzeMessages(content, pathToReport)

    # The 'content' object being passed in is of type org.sleuthkit.datamodel.Content
    # See http://www.sleuthkit.org/sleuthkit/docs/jni-docs/latest/interfaceorg_1_1sleuthkit_1_1datamodel_1_1_content.html
    # The 'content' object is assumed to be a Facebook Messenger (Beta) AppData directory with name 'Facebook.FacebookMessenger_8xx8rvfyw5nnt'
    def _analyzeCachedImages(self, content, path):
        pathToCachedImagesCSV = os.path.join(path, "report_images.csv")
        if not os.path.exists(pathToCachedImagesCSV):
            self.log(Level.INFO, "Unable to find cached images CSV report")
            return
        with open(pathToCachedImagesCSV, "r") as csvfile:  # Python 2.x doesn't allow 'encoding' keyword argument
            images = csv.reader(csvfile)  # TODO (ricardoapl) Add CSV delimiter ('~', '^')
            next(images)  # Ignore header row (i.e. first row)
            for image in images:
                sourceContent = self._getCachedImageSourceContent(content, image)
                self._newArtifactFBCachedImage(sourceContent, image)

    # The 'content' object being passed in is of type org.sleuthkit.datamodel.Content
    # See http://www.sleuthkit.org/sleuthkit/docs/jni-docs/latest/interfaceorg_1_1sleuthkit_1_1datamodel_1_1_content.html
    # The 'content' object is assumed to be a Facebook Messenger (Beta) AppData directory with name 'Facebook.FacebookMessenger_8xx8rvfyw5nnt'
    def _getCachedImageSourceContent(self, content, image):
        location, origin, timestamp, url = image

        # 'location' should resemble '...\Temp\<DataSourceId>\<Username>\AppData\Local\Packages\Facebook.FacebookMessenger_8xx8rvfyw5nnt\LocalState\Partitions\8bda49db...'
        # We just want to keep what's after <DataSourceId>
        locationParts = location.split("\\")
        sourceLocation = "\\".join(locationParts[-8:])

        dirName = os.path.join(sourceLocation, "Cache")
        # Autopsy expects forward slashes ('/') in paths so we have to replace any occurance of backward slashes ('\\')
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

    # The 'sourceFile' object being passed in is of type org.sleuthkit.datamodel.Content
    # See http://www.sleuthkit.org/sleuthkit/docs/jni-docs/latest/interfaceorg_1_1sleuthkit_1_1datamodel_1_1_content.html
    def _newArtifactFBCachedImage(self, sourceFile, image):
        # XXX (ricardoapl) Check if artifact already exists
        # See https://sleuthkit.discourse.group/t/clearing-a-blackboard-folder-each-time/265/3
        dateAccessed = image[2]
        url = image[3]

        # XXX (ricardoapl) Date/Time manipulation should be done in W10-FaceMessenger executable
        dateTimeFormat = "%Y-%m-%dT%H:%M:%S.%f"
        offsetFormat = "%H:%M"
        if "+" in dateAccessed:
            dateTimeString, offsetString = dateAccessed.split("+")
            dateTime = datetime.datetime.strptime(dateTimeString, dateTimeFormat)
            offset = datetime.datetime.strptime(offsetString, offsetFormat)
            offset = datetime.timedelta(hours=offset.hour, minutes=offset.minute)
            dateTime = dateTime + offset
        elif "-" in dateAccessed:
            dateString, utcOffset = dateAccessed.split("-")
            dateTime = datetime.datetime.strptime(dateTimeString, dateTimeFormat)
            offset = datetime.datetime.strptime(offsetString, offsetFormat)
            offset = datetime.timedelta(hours=offset.hour, minutes=offset.minute)
            dateTime = dateTime - offset
        timeStruct = dateTime.timetuple()
        timestamp = int(calendar.timegm(timeStruct))

        moduleName = W10FaceMessengerIngestModuleFactory.moduleName
        attributeUrl = BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_URL, moduleName, url)
        attributeDateTimeAccessed = BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME_ACCESSED, moduleName, timestamp)

        artifact = sourceFile.newArtifact(self.ARTIFACT_TYPE_FB_CACHED_IMAGE.getTypeID())
        artifact.addAttribute(attributeUrl)
        artifact.addAttribute(attributeDateTimeAccessed)

        return artifact

    def _analyzeLostFound(self, content, path):
        pathToLostFoundCSV = os.path.join(path, "report-undark.csv")
        if not os.path.exists(pathToLostFoundCSV):
            self.log(Level.INFO, "Unable to find undark CSV report")
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
        dbFile = contents.get(0)

        with open(pathToLostFoundCSV, "r") as csvfile:  # Python 2.x doesn't allow 'encoding' keyword argument
            lines = csvfile.readlines()
            records = lines[1:]  # Ignore header row (i.e. first row)
            for record in records:
                self._newArtifactFBLostFound(dbFile, record)

    # The 'sourceFile' object being passed in is of type org.sleuthkit.datamodel.Content
    # See http://www.sleuthkit.org/sleuthkit/docs/jni-docs/latest/interfaceorg_1_1sleuthkit_1_1datamodel_1_1_content.html
    # The 'sourceFile' object is assumed to be a Facebook Messenger (Beta) SQLite database file with name similar to 'msys_1234567890.db'
    def _newArtifactFBLostFound(self, sourceFile, record):
        moduleName = W10FaceMessengerIngestModuleFactory.moduleName
        attributeType = BlackboardAttribute.ATTRIBUTE_TYPE.TSK_TEXT
        attribute = BlackboardAttribute(attributeType, moduleName, record)
        artifactTypeId = self.ARTIFACT_TYPE_FB_LOST_FOUND.getTypeID()
        artifact = sourceFile.newArtifact(artifactTypeId)
        artifact.addAttribute(attribute)
        return artifact

    # The 'content' object being passed in is of type org.sleuthkit.datamodel.Content
    # See http://www.sleuthkit.org/sleuthkit/docs/jni-docs/latest/interfaceorg_1_1sleuthkit_1_1datamodel_1_1_content.html
    # The 'content' object is assumed to be a Facebook Messenger (Beta) AppData directory with name 'Facebook.FacebookMessenger_8xx8rvfyw5nnt'
    def _analyzeContacts(self, content, path):
        pathToContactsCSV = os.path.join(path, "contacts.csv")
        if not os.path.exists(pathToContactsCSV):
            self.log(Level.INFO, "Unable to find contacts CSV report")
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
        dbFile = contents.get(0)

        sleuthkitCase = Case.getCurrentCase().getSleuthkitCase()
        moduleName = W10FaceMessengerIngestModuleFactory.moduleName
        srcContent = dbFile
        accountType = Account.Type.FACEBOOK
        selfAccountId = "100047488492327"  # TODO (ricardoapl) Remove hardcoded identifier
        appDbHelper = CommunicationArtifactsHelper(sleuthkitCase, moduleName, srcContent, accountType, accountType, selfAccountId)

        with open(pathToContactsCSV, "r") as csvfile:  # Python 2.x doesn't allow 'encoding' keyword argument
            contacts = csv.reader(csvfile)  # TODO (ricardoapl) Add CSV delimiter ('~', '^')
            next(contacts)  # Ignore header row (i.e. first row)
            for contact in contacts:
                self._newArtifactFBContact(dbFile, contact)
                self._newArtifactTSKContact(appDbHelper, contact)

    # The 'sourceFile' object being passed in is of type org.sleuthkit.datamodel.Content
    # See http://www.sleuthkit.org/sleuthkit/docs/jni-docs/latest/interfaceorg_1_1sleuthkit_1_1datamodel_1_1_content.html
    # The 'sourceFile' object is assumed to be a Facebook Messenger (Beta) SQLite database file with name similar to 'msys_1234567890.db'
    def _newArtifactFBContact(self, sourceFile, contact):
        # XXX (ricardoapl) Check if artifact already exists
        # See https://sleuthkit.discourse.group/t/clearing-a-blackboard-folder-each-time/265/3
        facebookId = contact[0]
        displayName = contact[2]
        phone = contact[3]
        email = contact[4]
        profilePic = contact[5]

        moduleName = W10FaceMessengerIngestModuleFactory.moduleName
        attributeFacebookId = BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_USER_ID, moduleName, facebookId)
        attributeDisplayName = BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DISPLAY_NAME, moduleName, displayName)
        attributePhone = BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PHONE_NUMBER, moduleName, phone)
        attributeEmail = BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_EMAIL, moduleName, email)
        attributeProfilePic = BlackboardAttribute(self.ATTRIBUTE_TYPE_FB_PROFILE_PIC, moduleName, profilePic)

        artifact = sourceFile.newArtifact(self.ARTIFACT_TYPE_FB_CONTACT.getTypeID())
        artifact.addAttribute(attributeFacebookId)
        artifact.addAttribute(attributeDisplayName)
        artifact.addAttribute(attributePhone)
        artifact.addAttribute(attributeEmail)
        artifact.addAttribute(attributeProfilePic)

        return artifact

    # Wrapper method for org.sleuthkit.datamodel.blackboardutils.CommunicationArtifactsHelper.addContact
    # See http://sleuthkit.org/sleuthkit/docs/jni-docs/4.9.0//classorg_1_1sleuthkit_1_1datamodel_1_1blackboardutils_1_1_communication_artifacts_helper.html#a3e64e93ebc1aaec36c336b6f623ff7e7
    def _newArtifactTSKContact(self, appDbHelper, contact):
        facebookId = contact[0]
        contactName = contact[2]
        phoneNumber = contact[3]
        homePhoneNumber = ""
        mobilePhoneNumber = ""
        emailAddr = contact[4]

        moduleName = W10FaceMessengerIngestModuleFactory.moduleName
        attributeFacebookId = BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_ID, moduleName, facebookId)
        additionalAttributes = ArrayList()
        additionalAttributes.add(attributeFacebookId)

        artifact = appDbHelper.addContact(contactName, phoneNumber, homePhoneNumber, mobilePhoneNumber, emailAddr, additionalAttributes)

        return artifact

    # The 'content' object being passed in is of type org.sleuthkit.datamodel.Content
    # See http://www.sleuthkit.org/sleuthkit/docs/jni-docs/latest/interfaceorg_1_1sleuthkit_1_1datamodel_1_1_content.html
    # The 'content' object is assumed to be a Facebook Messenger (Beta) AppData directory with name 'Facebook.FacebookMessenger_8xx8rvfyw5nnt'
    def _analyzeMessages(self, content, path):
        pathToConversationsCSV = os.path.join(path, "conversations.csv")
        if not os.path.exists(pathToConversationsCSV):
            self.log(Level.INFO, "Unable to find conversations CSV report")
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
        dbFile = contents.get(0)

        participants = self._getParticipants(pathToConversationsCSV)

        sleuthkitCase = Case.getCurrentCase().getSleuthkitCase()
        moduleName = W10FaceMessengerIngestModuleFactory.moduleName
        srcContent = dbFile
        accountType = Account.Type.FACEBOOK
        selfAccountId = "100047488492327"  # TODO (ricardoapl) Remove hardcoded identifier
        appDbHelper = CommunicationArtifactsHelper(sleuthkitCase, moduleName, srcContent, accountType, accountType, selfAccountId)

        pathToThreads = os.path.join(path, "messages")
        threads = os.listdir(pathToThreads)
        if not threads:
            self.log(Level.INFO, "Unable to find messages CSV report(s)")
            return

        for thread in threads:
            threadId = thread.rsplit(".", 1)[0]  # Files are named after the threads, ignore their extension
            threadParticipants = participants[threadId]
            pathToMessagesCSV = os.path.join(pathToThreads, thread)
            with open(pathToMessagesCSV, "r") as csvfile:
                messages = csv.reader(csvfile)  # TODO (ricardoapl) Add CSV delimiter ('~', '^')
                next(messages)  # Ignore header row (i.e. first row)
                for message in messages:
                    self._newArtifactFBMessage(dbFile, message)
                    self._newArtifactTSKMessage(appDbHelper, message, threadParticipants, selfAccountId)

    def _getParticipants(self, path):
        participants = defaultdict(list)
        with open(path, "r") as csvfile:
            rows = csv.reader(csvfile)  # TODO (ricardoapl) Add CSV delimiter ('~', '^')
            next(rows)  # Ignore header row (i.e. first row)
            for row in rows:
                threadId = row[3]
                participantId = row[4]
                participants[threadId].append(participantId)
        return participants

    # The 'sourceFile' object being passed in is of type org.sleuthkit.datamodel.Content
    # See http://www.sleuthkit.org/sleuthkit/docs/jni-docs/latest/interfaceorg_1_1sleuthkit_1_1datamodel_1_1_content.html
    # The 'sourceFile' object is assumed to be a Facebook Messenger (Beta) SQLite database file with name similar to 'msys_1234567890.db'
    def _newArtifactFBMessage(self, sourceFile, message):
        # XXX (ricardoapl) Check if artifact already exists
        # See https://sleuthkit.discourse.group/t/clearing-a-blackboard-folder-each-time/265/3
        threadId = message[0]
        dateString = message[1]
        senderId = message[2]
        senderName = message[3]
        text = message[4]
        playableURL = message[6]

        formatString = "%Y-%m-%d %H:%M:%S"
        # We assume 'dateString' is in UTC/GMT
        dateTime = datetime.datetime.strptime(dateString, formatString)
        timeStruct = dateTime.timetuple()
        timestamp = int(calendar.timegm(timeStruct))

        moduleName = W10FaceMessengerIngestModuleFactory.moduleName
        attributeThreadId = BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_THREAD_ID, moduleName, threadId)
        attributeDateTime = BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME, moduleName, timestamp)
        attributeSenderId = BlackboardAttribute(self.ATTRIBUTE_TYPE_FB_USER_ID_FROM, moduleName, senderId)
        attributeSenderName = BlackboardAttribute(self.ATTRIBUTE_TYPE_FB_DISPLAY_NAME_FROM, moduleName, senderName)
        attributeText = BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_TEXT, moduleName, text)
        attributeAttachmentURL = BlackboardAttribute(self.ATTRIBUTE_TYPE_FB_URL_CONTENT, moduleName, playableURL)

        artifact = sourceFile.newArtifact(self.ARTIFACT_TYPE_FB_MESSAGE.getTypeID())
        artifact.addAttribute(attributeThreadId)
        artifact.addAttribute(attributeDateTime)
        artifact.addAttribute(attributeSenderId)
        artifact.addAttribute(attributeSenderName)
        artifact.addAttribute(attributeText)
        artifact.addAttribute(attributeAttachmentURL)

        return artifact

    # The 'content' object being passed in is of type org.sleuthkit.datamodel.Content
    # See http://www.sleuthkit.org/sleuthkit/docs/jni-docs/latest/interfaceorg_1_1sleuthkit_1_1datamodel_1_1_content.html
    # The 'content' object is assumed to be a Facebook Messenger (Beta) SQLite database file with name similar to 'msys_1234567890.db'
    def _newArtifactTSKMessage(self, appDbHelper, message, participants, selfAccountId):
        threadId = message[0]
        dateString = message[1]
        senderId = message[2]
        messageText = message[4]
        attachmentURL = message[6]

        formatString = "%Y-%m-%d %H:%M:%S"
        # We assume 'dateString' is in UTC/GMT
        dateTime = datetime.datetime.strptime(dateString, formatString)
        timeStruct = dateTime.timetuple()
        timestamp = int(calendar.timegm(timeStruct))

        subject = ""
        messageType = "Messenger (Beta)"
        direction = self._deduceMessageDirection(senderId, selfAccountId)
        recipientIdsList = [participantId for participantId in participants if participantId != senderId]
        readStatus = MessageReadStatus.UNKNOWN

        artifact = appDbHelper.addMessage(messageType, direction, senderId, recipientIdsList, timestamp, readStatus, subject, messageText, threadId)

        fileAttachments = ArrayList()
        urlAttachments = ArrayList()
        if (attachmentURL != ""):
            urlAttachments.add(URLAttachment(attachmentURL))
        messageAttachments = MessageAttachments(fileAttachments, urlAttachments)
        appDbHelper.addAttachments(artifact, messageAttachments)

        return artifact

    def _deduceMessageDirection(self, senderId, selfAccountId):
        direction = CommunicationDirection.UNKNOWN
        if senderId == selfAccountId:
            direction = CommunicationDirection.OUTGOING
        else:
            direction = CommunicationDirection.INCOMING
        return direction
