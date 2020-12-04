from expressionExecutor import callExpression, binaryExpression
from Left import leftIdentifierAssignment, leftMemberExpressionAssignment
from constants import SOURCES, SANITIZERS, SINKS

# This class describes the right side of assignments, because the side is important
# for the context.

leftAssignmentType = {
    'Identifier': leftIdentifierAssignment,
    'MemberExpression': leftMemberExpressionAssignment
}


# Everytime that a TAINTED variable is used in a test (if/while)
# the context will become TAINTED and if there is any type of assignment
# the left identifiers will become TAINTED
def checkImplicitFlow(left, ctx):
    ltype = left["type"]

    # If the context is tainted we know that the left side will instantly be tainted
    # therefore the assignment is instantly TAINTED
    if ctx.getContextTaint():
        leftAssignmentType[ltype](left, True, ctx, sourceName="Implicit Flow")
        return True
    return False


# A literal is always considered safe
def rightLiteralAssignment(right, left, ctx):
    if checkImplicitFlow(left, ctx):
        return True

    ltype = left["type"]
    leftAssignmentType[ltype](left, False, ctx)
    return False


# Check if the right side value is tainted
def rightIdentifierAssignment(right, left, ctx):
    if checkImplicitFlow(left, ctx):
        return True

    ltype = left["type"]
    varName = right["name"]

    if ctx.checkVariable(varName):
        leftAssignmentType[ltype](left, True, ctx, sourceName=ctx.getSource(varName))
        return True
    else:
        leftAssignmentType[ltype](left, False, ctx)
        return False


# In the right side of an assignment, a member expression can
# only be a source, if it is a source the left side variable
# will be tainted.
# PS: I don't think there are any memberExpression tests
def rightMemberExpressionAssignment(right, left, ctx):
    if checkImplicitFlow(left, ctx):
        return True

    functionName = right["callee"]["name"]
    ltype = left["type"]

    if ctx.searchInVulnPattern(functionName, SOURCES) != "":
        leftAssignmentType[ltype](left, True, ctx, sourceName=functionName)
        return True
    else:
        leftAssignmentType[ltype](left, False, ctx)
        return False


# In a Expression Assignment, function call's, can only be
# present in the right side
def rightCallExpressionAssignment(right, left, ctx):
    if checkImplicitFlow(left, ctx):
        return True

    functionName = right["callee"]["name"]
    ltype = left["type"]

    def sourceFunc(sourceName=functionName):
        leftAssignmentType[ltype](left, True, ctx, sourceName)
        return True

    def sanitizerFunc():
        leftAssignmentType[ltype](left, False, ctx)
        return False

    def sinkFunc():
        leftAssignmentType[ltype](left, True, ctx, sourceName=functionName)
        return

    # Function called when there is no tainted variable
    def defaultFunc():
        leftAssignmentType[ltype](left, False, ctx)
        return

    arguments = right["arguments"]
    return callExpression(functionName, ctx, arguments, sourceFunc, sanitizerFunc, sinkFunc, defaultFunc)


# In a expression assignment the right side can be of type: a = a+b | a = a+b+c...
# The variables involved in the binary expression must be checked to
# guarantee that none are TAINTED
def rightMemberBinaryExpression(right, left, ctx):
    if checkImplicitFlow(left, ctx):
        return True

    ltype = left["type"]

    # In a binary expression the source can result from a variable or function
    source = binaryExpression(right, ctx)
    if source != "":
        leftAssignmentType[ltype](left, True, ctx, sourceName=source)
        return True
    else:
        leftAssignmentType[ltype](left, False, ctx)
        return False


