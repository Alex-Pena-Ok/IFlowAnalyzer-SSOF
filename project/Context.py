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

    # Add's a vulnerability to the program context or updates is list of sources/sink
    # if it already exists
    def addVulnerability(self, vulnerability):
        vuln = None
        for vulnsFound in self.vulnerabilitiesFound:
            if vulnsFound.getVulnerability() == vulnerability.getVulnerability():
                vulnsFound.updateVulnerability(vulnerability)
                return

        self.vulnerabilitiesFound.append(vulnerability)

        # Set's the pair of sanitizers for the given vulnerability
        for vulnPattern in self.vulnerabilitiesInPattern:
            if vulnPattern.getVulnerability() == vulnerability.getVulnerability():
                vulnerability.setSanitizer(vulnPattern.getSanitizers())

    # Add's a variable to the program context or updates it if it already exists
    def addVariable(self, newVariable):
        # Check if variable already exists, if so just update it
        for var in self.variables:
            if newVariable.getName() == var.getName():
                var.setTainted(newVariable.getTainted())
                src = newVariable.getSource()
                if src != var.getName():
                    var.setSource(src)
                return
        self.variables.append(newVariable)

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
            self.merge(new_ctx_consequent, True)
        else:
            self.merge(new_ctx_consequent)  # We don't know if the if was taken, therefore not newPrivileged path
        return

    def merge(self, new_context, newPrivileged=False):
        for varNewCtx in new_context.variables:
            found = False
            for varCurrCtx in self.variables:
                if varCurrCtx.getName() == varNewCtx.getName():
                    found = True
                    if not newPrivileged:
                        # If any of the contexts has the curr variable has TAINTED
                        # the end result will also de TAINTED
                        # The not condition is to not clear the source of the variable
                        if varNewCtx.getTainted() and not varCurrCtx.getTainted():
                            varCurrCtx.setTainted(True)
                            varCurrCtx.setSource(varNewCtx.getSource())
                    else:
                        # The 'newPrivileged' path means that the result context 'new_context' was merged with a
                        # 'new_ctx_alternate' (alternate block) which means there was an ELSE to the condition
                        # if the IF didn't execute we are sure the ELSE did, and there could have been a potentially
                        # sanitizer function in the else, which the not newPrivileged path would ignore and still
                        # consider it tainted.
                        # e.g.
                        # a = source()
                        # if (...) { b() } else { a = sanitizer(a) }
                        # This path is only taken when its time to merge a main context (previous to the IfStatement)
                        # with the newContext which resulted from the TAINTED 'OR' merge
                        # of consequentCtx with alternateCtx
                        varCurrCtx.setTainted(varNewCtx.getTainted())
                        varCurrCtx.setSource(varNewCtx.getSource())

            # variable was not declared before the context of the block consequent or alternate
            # we must then add it to the main context before leaving or it would disappear
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
