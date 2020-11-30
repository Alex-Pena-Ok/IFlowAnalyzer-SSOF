from Variable import Variable
from Vulnerability import Vulnerability
from VulnerabilityPattern import VulnerabilityPattern


# This class contains the context of the program execution, aka. variables found, vulnerabilities...

# Create Vulnerability
def createVulnerability(vulnName, source, sink, variable):
    # Vulnerability found, passing a tainted variable to a sink
    vuln = Vulnerability()
    vuln.sink = sink
    vuln.variable = variable
    vuln.name = vulnName
    vuln.source = source


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
        self.variables.append(variable)

    # Check's if the current variable is tainted or not,
    # if the variable doesn't exist yet in the current context creates it untainted.
    def checkVariable(self, variableName):
        for currVar in self.variables:
            if currVar.name == variableName:
                if currVar.tainted:
                    return True

        # Variable does not exist yet, therefore create it, untainted
        var = Variable(variableName, False)
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
                return vuln.vulnerability
        return ""

    # Outputs the conclusion of the analysis tool
    def writeOutput(self):
        print("Analysis Result:\n")

        if len(self.vulnerabilitiesFound) == 0:
            print("No vulnerabilities found.")
        else:
            for vuln in self.vulnerabilitiesFound:
                print("Vulnerability: %s | Source: %s | Sink: %s | Variable: %s\n" %
                      vuln.vulnerability, vuln.source, vuln.sink, vuln.variable.name)