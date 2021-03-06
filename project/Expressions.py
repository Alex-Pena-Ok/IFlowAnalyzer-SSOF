from expressionExecutor import callExpression, binaryExpression
from Right import rightLiteralAssignment, rightMemberExpressionAssignment, rightCallExpressionAssignment, \
    rightIdentifierAssignment, rightMemberBinaryExpression

rightAssignmentType = {
    'Literal': rightLiteralAssignment,
    'Identifier': rightIdentifierAssignment,
    'CallExpression': rightCallExpressionAssignment,
    'MemberExpression': rightMemberExpressionAssignment,
    'BinaryExpression': rightMemberBinaryExpression
}


# Executes an AssignmentExpression, a = b | a = b() | a = document.url | document.url = a | document.url = a()
# The result of this function doesn't matter for the IF and WHILE statements
def executeAssignment(step, ctx):
    left = step["left"]  # In AssignmentExpressions, left type is always 'Identifier' or 'MemberExpression'
    right = step["right"]  # The type of right can be 'MemberExpression', 'CallExpression' or 'Literal'
    rtype = right["type"]

    return rightAssignmentType[rtype](right, left, ctx)


# Executes a CallExpression, e.g. a() | a(b) | a(b()) | a(b(c('ola'))) | a(b(c(d)))
def executeCall(step, ctx):
    functionName = step["callee"]["name"]

    arguments = step["arguments"]
    return callExpression(functionName, ctx, arguments)


# Executes a BinaryExpression, e.g. a == b (the left or right can be an MemberExpression)
# This one can only be called by IfStatementes and WhileStatements
# It's necessary to check if the variables involved in the tests are TAINTED or UNTAINTED
def executeBinaryExpression(step, ctx):
    return True if binaryExpression(step, ctx) != "" else False

