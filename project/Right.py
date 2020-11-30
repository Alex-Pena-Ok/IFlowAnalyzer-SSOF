from Left import leftIdentifierAssignment, leftMemberExpressionAssignment
from constants import SOURCES, SANITIZERS, SINKS

# This class describes the right side of assignments, because the side is important
# for the context.

leftAssignmentType = {
    'Identifier': leftIdentifierAssignment,
    'MemberExpression': leftMemberExpressionAssignment
}


# A literal is always considered safe
def rightLiteralAssignment(right, left, ctx):
    ltype = left["type"]
    leftAssignmentType[ltype](left, False, ctx)
    return


# Check if the right side value is tainted
def rightIdentifierAssignment(right, left, ctx):
    ltype = left["type"]
    varName = right["name"]

    if ctx.checkVariable(varName):
        leftAssignmentType[ltype](left, True, ctx, sourceName=ctx.getSource(varName))
    else:
        leftAssignmentType[ltype](left, False, ctx)
    return


# In a Expression Assignment, function call's, can only be
# present in the right side
def rightCallExpressionAssignment(right, left, ctx):
    functionName = right["callee"]["name"]
    ltype = left["type"]

    # Check if the CallExpression callee is a source
    # if it's a source, it's parameters don't really matter.
    if ctx.searchInVulnPattern(functionName, SOURCES) != "":
        leftAssignmentType[ltype](left, True, ctx, sourceName=functionName)
        return

    # Check if the CallExpression calle is a sanitizer
    # I assumed here that the sanitizer returns a new sanitized variable
    # instead of 'sanitizing' the one passed to it as argument
    # therefore the old one keeps tainted.
    if ctx.searchInVulnPattern(functionName, SANITIZERS) != "":
        leftAssignmentType[ltype](left, False, ctx)
        return

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
                leftAssignmentType[ltype](left, True, ctx, sourceName=functionName)  # Im considering that the output of the sink is also tainted
                return

    # The right side function is neither source, sink or sanitizer, some random function therefore
    # variable created is considered untainted
    #TODO: If its not sanitizer, sink or source and its another nested function, the nested function must be checked too
    # recursively call same function?
    leftAssignmentType[ltype](left, False, ctx)
    return


# In the right side of an assignment, a member expression can
# only be a source, if it is a source the left side variable
# will be tainted.
# TODO: I don't think there are any memberExpression tests
def rightMemberExpressionAssignment(right, left, ctx):
    functionName = right["callee"]["name"]
    ltype = left["type"]

    if ctx.searchInVulnPattern(functionName, SOURCES) != "":
        leftAssignmentType[ltype](left, True, ctx, sourceName=functionName)
    else:
        leftAssignmentType[ltype](left, False, ctx)
    return
