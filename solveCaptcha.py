import re
from burp import IBurpExtender
from burp import IExtensionStateListener
from burp import IHttpListener
from burp import IParameter
from java.io import PrintWriter


class BurpExtender(IBurpExtender, IExtensionStateListener, IHttpListener, IParameter):
    
    def __init__(self):
        self.extension_name = "Solve Captcha Extension"
        self.author = "Me"

    def echo(self, data):
        self.stdout.println(data)

    def extensionUnloaded(self):
        self.echo("Unloaded")


    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        self.stdout = PrintWriter(callbacks.getStdout(), True)
        self.stderr = PrintWriter(callbacks.getStderr(), True)

        self._callbacks.registerExtensionStateListener(self)
        self._callbacks.registerHttpListener(self)

        self._callbacks.setExtensionName(self.extension_name)
        self.echo("Extension name: " + self.extension_name)


    def solveCaptcha(self, IHttpInterface, requestBytes):
       IHttpRequestResponse = self._callbacks.makeHttpRequest(IHttpInterface, requestBytes)
       responseBytes =  IHttpRequestResponse.getResponse()
       responseString = self._helpers.bytesToString(responseBytes)

       regex = r'\nCaptcha\: (.*?)=<input'
       captcha = re.compile(regex).findall(responseString)

       if captcha:
           captcha = captcha[0]
           self.echo(captcha)
           regex = r'.\d+'
           captcha = re.compile(regex).findall(captcha)
           res = 0
           for n in captcha:
               res += int(n)

           self.echo(res)
           return res
       

       return ""
       

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
    
        if toolFlag != self._callbacks.TOOL_INTRUDER:
            return


        IHttpInterface = messageInfo.getHttpService()

        if messageIsRequest:
            requestBytes = messageInfo.getRequest()
            requestAnalyze = self._helpers.analyzeRequest(requestBytes)

            requestHeaders = requestAnalyze.getHeaders()
            requestMethod = requestAnalyze.getMethod()

            requestParameters = requestAnalyze.getParameters()

            captchaParam = None

            for param in requestParameters:
                if param.getName() == "captcha":
                    captchaParam = param

            if captchaParam is None:
                return            

            if toolFlag == self._callbacks.TOOL_INTRUDER:

                captchaParamValNew = self.solveCaptcha(IHttpInterface, self._helpers.toggleRequestMethod(requestBytes))
                
                captchaParameter = self._helpers.buildParameter(captchaParam.getName(), str(captchaParamValNew), IParameter.PARAM_BODY)

                finalHttpRequest = self._helpers.updateParameter(requestBytes, captchaParameter)

                messageInfo.setRequest(finalHttpRequest)
            


        

