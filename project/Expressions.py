from Left import leftMemberExpressionAssignment, leftIdentifierAssignment
from Right import rightLiteralAssignment, rightMemberExpressionAssignment, rightCallExpressionAssignment

rightAssignmentType = {
    'Literal': rightLiteralAssignment,
    'CallExpression': rightCallExpressionAssignment,
    'MemberExpression': rightMemberExpressionAssignment
}

leftAssignmentType = {
    'Identifier': leftIdentifierAssignment,
    'MemberExpression': leftMemberExpressionAssignment
}


# Executes an AssignmentExpression, a = b | a = b() | a = document.url | document.url = a | document.url = a()
def executeAssignment(step):
    left = step["left"]  # In AssignmentExpressions, left type is always 'Identifier' or 'MemberExpression'
    right = step["right"]  # The type of right can be 'MemberExpression', 'CallExpression' or 'Literal'

    rtype = right["type"]
    ltype = left["type"]

    rightAssignmentType[rtype](right)
    leftAssignmentType[ltype](left)


# Executes a CallExpression, e.g. a() | a(b()) | a(b)
def executeCall(step):
    #TODO
    print("TODO")


# Executes a BinaryExpression, e.g. a == b (the left or right can be an MemberExpression)
def executeBinaryExpression(step):
    #TODO
    print("TODO")
