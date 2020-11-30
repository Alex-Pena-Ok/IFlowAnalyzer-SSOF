from Right import rightLiteralAssignment, rightMemberExpressionAssignment, rightCallExpressionAssignment, \
    rightIdentifierAssignment
from constants import SINKS, SOURCES, SANITIZERS

rightAssignmentType = {
    'Literal': rightLiteralAssignment,
    'Identifier': rightIdentifierAssignment,
    'CallExpression': rightCallExpressionAssignment,
    'MemberExpression': rightMemberExpressionAssignment
}


# Executes an AssignmentExpression, a = b | a = b() | a = document.url | document.url = a | document.url = a()
def executeAssignment(step, ctx):
    left = step["left"]  # In AssignmentExpressions, left type is always 'Identifier' or 'MemberExpression'
    right = step["right"]  # The type of right can be 'MemberExpression', 'CallExpression' or 'Literal'
    rtype = right["type"]

    rightAssignmentType[rtype](right, left, ctx)


# Executes a CallExpression, e.g. a() | a(b) | a(b()) | a(b(c('ola'))) | a(b(c(d)))
def executeCall(step, ctx):
    functionName = step["callee"]["name"]

    # If it's a SOURCE the output is considered as tainted
    if ctx.searchInVulnPattern(functionName, SOURCES) != "":
        return True

    # If it's a sanitizer the returned output is UNTAINTED
    if ctx.searchInVulnPattern(functionName, SANITIZERS) != "":
        return False

    # If it's a sink and one of the arguments is tainted
    # there is a vulnerability here
    vulnName = ctx.searchInVulnPattern(functionName, SINKS)
    if vulnName != "":
        arguments = step["arguments"]
        # Check if the CallExpression callee argument is tainted
        for argument in arguments:
            argumentName = argument["name"]
            if ctx.checkVariable(argumentName):  # Variable is TAINTED, vulnerability detected
                vuln = ctx.createVulnerability(vulnName, ctx.getSource(argumentName), functionName, argumentName)
                ctx.addVulnerability(vuln)
                return True  # Output TAINTED because the sink was compromised

    # It's not a sanitizer, sink or source... (any possible function)
    #TODO: If its not sanitizer, sink or source and its another nested function, the nested function must be checked too
    # recursivamente call function?
    return False


# Executes a BinaryExpression, e.g. a == b (the left or right can be an MemberExpression)
# This one can only be called by IfStatementes and WhileStatements
# It's necessary to check if the variables involved in the tests are TAINTED or UNTAINTED
def executeBinaryExpression(step, ctx):
    #TODO
    print("TODO")
    return
