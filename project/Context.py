import json

from Variable import Variable
from Vulnerability import Vulnerability
from VulnerabilityPattern import VulnerabilityPattern


# This class contains the context of the program execution, aka. variables found, vulnerabilities...
from constants import SOURCES


class Context:
    # Keeps track of the state of the program during "execution"
    vulnerabilitiesInPattern = []
    vulnerabilitiesFound = []
    variables = []
    taint = False

    # Add's a vulnerability to the program context
    def addVulnerability(self, vulnerability):
        self.vulnerabilitiesFound.append(vulnerability)

    # Add's a variable to the program context
    def addVariable(self, variable):
        # Check if variable already exists, if so just update it
        for var in self.variables:
            if variable.getName() == var.getName():
                var.setTainted(variable.getTainted())
                var.setSource(variable.getSource())
                return
        self.variables.append(variable)

    # Check's if the current variable is tainted or not,
    # if the variable doesn't exist yet in the current context creates it untainted.
    def checkVariable(self, variableName):
        for currVar in self.variables:
            if currVar.name == variableName:
                if currVar.tainted:
                    return True

        # Variable does not exist yet, therefore create it, untainted
        var = Variable(variableName, False, "Doesn't matter")
        return False

    # Initialize vulnerability pattern structures
    def initVulnPattern(self, vulnPattern):
        for vuln in vulnPattern:
            self.vulnerabilitiesInPattern.append(
                VulnerabilityPattern(
                    vuln["vulnerability"],
                    vuln["sources"],
                    vuln["sanitizers"],
                    vuln["sinks"]
                )
            )

    # Searches if the element in question is present in any
    # of the vulnerability patterns provided.
    # The type of element can be 'sources', 'sanitizers' or 'sinks'.
    # e.g. searchInVulns("document.url", "sources")
    # Returns the name of the vulnerability if the element is associated
    # with it's sink or source, otherwise empty string.
    def searchInVulnPattern(self, element, etype):
        for vuln in self.vulnerabilitiesInPattern:
            list = vuln.getList(etype)
            if element in list:
                return vuln.getVulnerability()
        return ""

    # Create Vulnerability
    def createVulnerability(self, vulnName, taintedVariable, sink):
        # Vulnerability found, passing a tainted variable to a sink
        vuln = Vulnerability()
        vuln.setSink(sink)
        vuln.setName(vulnName)
        vuln.setSource(self.getSource(taintedVariable))

        for vulnPattern in self.vulnerabilitiesInPattern:
            if vulnPattern.getVulnerability() == vulnName:
                vuln.setSanitizer(vulnPattern.getSanitizers())
                break

        return vuln

    # Gets the source associated with the TAINTED variable
    # it does that by running the chain of TAINTED variables until
    # it reaches the root SOURCE
    def getSource(self, argumentName):
        for var in self.variables:
            if var.getName() == argumentName:
                source = var.getSource()
                if self.searchInVulnPattern(source, SOURCES) != "":
                    return source
                else:
                    return self.getSource(source)   # Finds the SOURCE of this TAINTED variable recursively
        return "SOURCE NOT FOUND"

    # Outputs the conclusion of the analysis tool
    def writeOutput(self):
        print("Analysis Result:")

        if len(self.vulnerabilitiesFound) == 0:
            print("No vulnerabilities found.")
        else:
            for vuln in self.vulnerabilitiesFound:
                obj = {
                    "vulnerability": vuln.getVulnerability(),
                    "source": vuln.getSource(),
                    "sink": vuln.getSink(),
                    "sanitizer": vuln.getSanitizer()
                }
                print(json.dumps(obj))
