
# Variable can be tainted or not
from Variable import Variable


def leftIdentifierAssignment(left, tainted, ctx):
    #TODO
    return


# In case the left operator is an MemberExpression, it can be a sink
def leftMemberExpressionAssignment(left, tainted, ctx):
    #TODO
    return


# Called back by the left type
def createVariable(varName, tainted, ctx):
    varName = varName
    var = Variable(varName, tainted)
    ctx.addVariable(var)
    return
