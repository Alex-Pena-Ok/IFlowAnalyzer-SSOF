import json

from Variable import Variable
from Vulnerability import Vulnerability
from VulnerabilityPattern import VulnerabilityPattern


# This class contains the context of the program execution, aka. variables found, vulnerabilities...
from constants import SOURCES


class Context:
    def __init__(self):
        # Keeps track of the state of the program during "execution"
        self.vulnerabilitiesFound = []
        self.vulnerabilitiesInPattern = []
        self.variables = []
        self.taint = False

    # Add's a vulnerability to the program context
    def addVulnerability(self, vulnerability):
        self.vulnerabilitiesFound.append(vulnerability)

    # Add's a variable to the program context or updates it if it already exists
    def addVariable(self, variable):
        # Check if variable already exists, if so just update it
        for var in self.variables:
            if variable.getName() == var.getName():
                var.setTainted(variable.getTainted())
                var.setSource(variable.getSource())
                return
        self.variables.append(variable)

    # Check's if the current variable is tainted or not
    def checkVariable(self, variableName):
        for currVar in self.variables:
            # Variable exists
            if currVar.name == variableName:
                if currVar.tainted:
                    return True
                else:
                    return False

        # Variable does not exist yet, therefore create it, untainted
        # e.g. used in function arguments for the first time
        sourceVar = True if self.searchInVulnPattern(variableName, SOURCES) != "" else False
        source = variableName if sourceVar else "Couldn't find source"
        var = Variable(variableName, sourceVar, source)
        self.addVariable(var)

        return sourceVar

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
        return argumentName

    # Merges all tainted variables and vulnerabilities from the different contexts into the current context
    # Different flows can result in different state of variables
    # in one of the blocks a TAINTED variable can appear
    # and in the other a TAINTED variable can pass to UNTAINTED
    # with a sanitizer.
    # Even thought a vulnerability can be detected in each respective block context
    # when the IfStatement is over the program will continue and must
    # chose one of the generated contexts to continue with the program execution.
    # As the goal is to find possible vulnerabilities the 2 contexts are mixed
    # into one worst case scenario context which is used to detect all possible vulnerabilities.
    def mergeContexts(self, new_ctx_consequent, new_ctx_alternate):
        if new_ctx_alternate is not None:
            # We are doing an "OR" type of merge in tainted variables,
            # if in one of the contexts the var is TAINTED it will stay TAINTED
            # but if in both contexts the var is UNTAINTED in the final merge
            # the var must be tainted
            new_ctx_consequent.merge(new_ctx_alternate)
            self.merge(new_ctx_consequent)
        else:
            self.merge(new_ctx_consequent)
        return

    def merge(self, new_context):
        for varNewCtx in new_context.variables:
            found = False
            for varCurrCtx in self.variables:
                if varCurrCtx.getName() == varNewCtx.getName():
                    found = True
                    # If any of the contexts has the curr variable has TAINTED
                    # the end result will also de TAINTED
                    if varNewCtx.getTainted() and not varCurrCtx.getTainted():
                        varCurrCtx.setTainted(True)
                        varCurrCtx.setSource(varNewCtx.getSource())

            if not found:
                self.addVariable(varNewCtx)

        # If a var is found in the new context but not in the context to merge, it is ignored
        # because was a local variable that ceased to exist now

        # Add's the vulnerability to the current context if it doesn't exist already
        for vulnsFoundNewCtx in new_context.vulnerabilitiesFound:
            if not self.searchVulnerability(vulnsFoundNewCtx):
                self.vulnerabilitiesFound.append(vulnsFoundNewCtx)

    # Returns true if the vulnerability already exists in the context
    # a vulnerability must be unique to return True, for it to be unique
    # the pair name;sources;sink must have at least 1 difference between them
    def searchVulnerability(self, vulnerability):
        for vulnsFound in self.vulnerabilitiesFound:
                if vulnsFound.compare(vulnerability):
                    return True
        return False

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
