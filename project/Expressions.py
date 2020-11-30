from Right import rightLiteralAssignment, rightMemberExpressionAssignment, rightCallExpressionAssignment

rightAssignmentType = {
    'Literal': rightLiteralAssignment,
    'CallExpression': rightCallExpressionAssignment,
    'MemberExpression': rightMemberExpressionAssignment
}


# Executes an AssignmentExpression, a = b | a = b() | a = document.url | document.url = a | document.url = a()
def executeAssignment(step, ctx):
    left = step["left"]  # In AssignmentExpressions, left type is always 'Identifier' or 'MemberExpression'
    right = step["right"]  # The type of right can be 'MemberExpression', 'CallExpression' or 'Literal'
    rtype = right["type"]

    rightAssignmentType[rtype](right, left, ctx)

# Executes a CallExpression, e.g. a() | a(b()) | a(b)
def executeCall(step, ctx):
    #TODO
    print("TODO")
    return "bool tainted or not"


# Executes a BinaryExpression, e.g. a == b (the left or right can be an MemberExpression)
def executeBinaryExpression(step, ctx):
    #TODO
    print("TODO")
    return "bool tainted or not"
