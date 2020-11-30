from Left import leftIdentifierAssignment, leftMemberExpressionAssignment
from Variable import Variable

# This class describes the right side of assignments, because the side is important
# for the context.

SINKS = "sinks"
SOURCES = "sources"
SANITIZERS = "sanitizers"

leftAssignmentType = {
    'Identifier': leftIdentifierAssignment,
    'MemberExpression': leftMemberExpressionAssignment
}


# A literal is always considered safe
def rightLiteralAssignment(right, ctx):
    return


# In a Expression Assignment, function call's, can only be
# present in the right side
def rightCallExpressionAssignment(right, left, ctx):
    functionName = right["callee"]["name"]
    ltype = left["type"]

    # Check if the CallExpression callee is a source
    # if it's a source, it's parameters don't really matter.
    if ctx.searchInVulnPattern(functionName, SOURCES):
        leftAssignmentType[ltype](left, True, ctx)

    # Check if the CallExpression calle is a sanitizer
    # I assumed here that the sanitizer returns a new sanitized variable
    # instead of 'sanitizing' the one passed to it as argument
    # therefore the old one keeps tainted.
    if ctx.searchInVulnPattern(functionName, SANITIZERS):
        leftAssignmentType[ltype](left, False, ctx)

    # Check if the CallExpression callee is a sink, in this
    # case the parameter it receives matters.
    vulnName = ctx.searchInVulnPattern(functionName, SINKS)
    if vulnName != "":
        arguments = right["arguments"]
        # Check if the CallExpression callee argument is tainted
        for argument in arguments:
            if ctx.checkVariable(argument["name"]):  # Variable is TAINTED, vulnerability detected
                vuln = ctx.createVulnerability(vulnName, "", functionName, argument["name"])
                ctx.addVulnerability(vuln)
                return


# In the right side of an assignment, a member expression can
# only be a source, if it is a source the left side variable
# will be tainted.
def rightMemberExpressionAssignment(right, ctx):
    # TODO
    return
