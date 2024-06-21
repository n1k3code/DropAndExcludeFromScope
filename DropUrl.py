# Extension:    Drop URL and Exclude from scope
# Author:       Rodrigo Ramos
# Github:       https://github.com/n1k3code/
# Linkedin:     https://www.linkedin.com/in/rodrigoramospentester/

from burp import IBurpExtender, IProxyListener
from java.io import PrintWriter
from java.net import URL

class BurpExtender(IBurpExtender, IProxyListener):

    # Insert the targets here to exclude from scope
    _blackList = [
        "https://google.com"
    ]

    def	registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("DROP URL and Exclude from Scope (Rodrigo Ramos N1k3Code)")
        self._callbacks.registerProxyListener(self)
        self._stdout = PrintWriter(callbacks.getStdout(), True)
        self._stdout.println("Activated!")
        self.excludeScope(self._blackList)

    def excludeScope(self, _blackList):
        for url in _blackList:
            self._callbacks.excludeFromScope(URL(url))

    def parseHost(parsedUrl):
        scheme = parsedUrl.getProtocol()
        host = parsedUrl.getHost()
        newUrlStr = scheme+"://"+host
        newUrl = URL(newUrlStr)
        return newUrl

    def processProxyMessage(self, messageIsRequest, message):
        if messageIsRequest:
            
            messageInfo = message.getMessageInfo()
            requestInfo = self._helpers.analyzeRequest(messageInfo)
            
            url = str(requestInfo.getUrl())
            newUrl = parseHost(requestInfo.getUrl())
            
            if self._exclude in url:
                self._stdout.println("Dropped")
                message.setInterceptAction(message.ACTION_DROP)
            else:
                if not self._callbacks.isInScope(newUrl):
                    self._callbacks.includeInScope(newUrl)
