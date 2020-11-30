from expressionExecutor import callExpression, binaryExpression
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


# In the right side of an assignment, a member expression can
# only be a source, if it is a source the left side variable
# will be tainted.
# PS: I don't think there are any memberExpression tests
def rightMemberExpressionAssignment(right, left, ctx):
    functionName = right["callee"]["name"]
    ltype = left["type"]

    if ctx.searchInVulnPattern(functionName, SOURCES) != "":
        leftAssignmentType[ltype](left, True, ctx, sourceName=functionName)
    else:
        leftAssignmentType[ltype](left, False, ctx)
    return


# In a Expression Assignment, function call's, can only be
# present in the right side
def rightCallExpressionAssignment(right, left, ctx):
    functionName = right["callee"]["name"]
    ltype = left["type"]

    sourceFunc = lambda: leftAssignmentType[ltype](left, True, ctx, sourceName=functionName)
    sanitizerFunc = lambda: leftAssignmentType[ltype](left, False, ctx)
    sinkFunc = lambda: leftAssignmentType[ltype](left, True, ctx, sourceName=functionName)  # Im considering that the output of the sink is also tainted
    arguments = right["arguments"]
    return callExpression(functionName, ctx, sourceFunc, sanitizerFunc, sinkFunc, arguments)


# In a expression assignment the right side can be of type: a = a+b | a = a+b+c...
# The variables involved in the binary expression must be checked to
# guarantee that none are TAINTED
def rightMemberBinaryExpression(right, left, ctx):
    ltype = left["type"]

    # In a binary expression the source can result from a variable or function
    source = binaryExpression(right, ctx)
    if source != "":
        leftAssignmentType[ltype](left, True, ctx, sourceName=source)
    else:
        leftAssignmentType[ltype](left, False, ctx)
    return


