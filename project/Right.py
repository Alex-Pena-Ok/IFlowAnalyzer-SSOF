from Variable import Variable
from analProgram import searchInVulnPattern, addVulnerability, checkVariable, addVariable, createVulnerability

# This class describes the right side of assignments, because the side is important
# for the context.

SINKS = "sinks"
SOURCES = "sources"
SANITIZERS = "sanitizers"


# A literal is always considered safe
def rightLiteralAssignment(right):
    return


# In a Expression Assignment, function call's, can only be
# present in the right side
def rightCallExpressionAssignment(right):
    functionName = right["callee"]["name"]

    # Check if the CallExpression callee is a source
    # if it's a source, it's parameters don't really matter.
    if searchInVulnPattern(functionName, SOURCES):
        var = Variable(right["name"], True)
        addVariable(var)
        return

    # Check if the CallExpression calle is a sanitizer
    if searchInVulnPattern(functionName, SANITIZERS):
        var = Variable(right["name"], False)  # Variable was sanitized, therefore untainted
        addVariable(var)
        return

    # Check if the CallExpression callee is a sink, in this
    # case the parameter it receives matters.
    vulnName = searchInVulnPattern(functionName, SINKS)
    if vulnName != "":
        arguments = right["arguments"]
        # Check if the CallExpression callee argument is tainted
        for argument in arguments:
            if checkVariable(argument["name"]): # Variable is TAINTED, vulnerability detected
                vuln = createVulnerability(vulnName, "", functionName, argument["name"])
                addVulnerability(vuln)
                return


# In the right side of an assignment, a member expression can
# only be a source, if it is a source the left side variable
# will be tainted.
def rightMemberExpressionAssignment():
    # TODO
    return
