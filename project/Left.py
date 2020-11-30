from Variable import Variable
from constants import SINKS


def leftIdentifierAssignment(left, tainted, ctx, sourceName=""):
    createVariable(left['name'], tainted, ctx)
    return


# In case the left operator is an MemberExpression, it can be a sink
def leftMemberExpressionAssignment(left, tainted, ctx, sourceName=""):
    memberName = left['name']

    # If the memberExpression on the left side is a sink and
    # the variable is tainted, vulnerability was detected
    vulnName = ctx.searchInVulnPattern(memberName, SINKS)
    if vulnName != "" and tainted:
        vuln = ctx.createVulnerability(vulnName, sourceName, memberName, sourceName)
        ctx.addVulnerability(vuln)

    createVariable(memberName, tainted, ctx)


# Creates a variable and add's it to the program analysis context
def createVariable(varName, tainted, ctx):
    varName = varName
    var = Variable(varName, tainted)
    ctx.addVariable(var)
    return
