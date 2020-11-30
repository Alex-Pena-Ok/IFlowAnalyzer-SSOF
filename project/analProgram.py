from Statements import checkSteps, checkExpressionStatement, checkBlockStatement, checkWhileStatement, checkIfStatement
from Variable import Variable
from Vulnerability import Vulnerability
from VulnerabilityPattern import VulnerabilityPattern

# Keeps track of the state of the program during "execution"
vulnerabilitiesInPattern = []
vulnerabilitiesFound = []
variables = []

def analyzeProgram(programJson, vulnPattern):
    programSteps = programJson["body"]
    initVulnPattern(vulnPattern)

    # Analyzes program
    checkSteps(programSteps)

    # Concludes program execution
    writeOutput()

# Initialize vulnerability pattern structures
def initVulnPattern(vulnPattern):
    for vuln in vulnPattern:
        vulnerabilitiesInPattern.append(
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
def searchInVulnPattern(element, etype):
    for vuln in vulnerabilitiesInPattern:
        if element in vuln[etype]:
            return vuln.vulnerability
    return ""


# Add's a variable to the program context
def addVariable(variable):
    variables.append(variable)


# Create Vulnerability
def createVulnerability(vulnName, source, sink, variable):
    # Vulnerability found, passing a tainted variable to a sink
    vuln = Vulnerability()
    vuln.sink = sink
    vuln.variable = variable
    vuln.name = vulnName
    vuln.source = source


# Add's a vulnerability to the program context
def addVulnerability(vulnerability):
    vulnerabilitiesFound.append(vulnerability)


# Check's if the current variable is tainted or not,
# if the variable doesn't exist yet in the current context creates it untainted.
def checkVariable(variableName):
    for currVar in variables:
        if currVar.name == variableName:
            if currVar.tainted:
                return True

    # Variable does not exist yet, therefore create it, untainted
    var = Variable(variableName, False)
    return False


# Outputs the conclusion of the analysis tool
def writeOutput():
    print("Analysis Result:\n")

    if len(vulnerabilitiesFound) == 0:
        print("No vulnerabilities found.")
    else:
        for vuln in vulnerabilitiesFound:
            print("Vulnerability: %s | Source: %s | Sink: %s | Variable: %s\n" %
                  vuln.vulnerability, vuln.source, vuln.sink, vuln.variable.name)