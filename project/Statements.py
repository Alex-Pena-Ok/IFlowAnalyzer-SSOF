from Expressions import executeAssignment, executeCall, executeBinaryExpression

# Dictionary to map between the expression type and the actual function to call
expressionTypes = {
    'AssignmentExpression': executeAssignment,
    'CallExpression': executeCall,
    'BinaryExpression': executeBinaryExpression
}


# Executes an ExpressionStatement, assignments or function call's
def checkExpressionStatement(step):
    expression = step["expression"]
    expressionType = expression["type"]
    expressionTypes[expressionType](expression)

# Executes an IfStatement, binary expressions
def checkIfStatement(step):
    #TODO
    print("TODO")


# Executes a WhileStatement
def checkWhileStatement(step):
    #TODO
    print("TODO")


# Executes a BlockStatement, called by while & if's, can have any of the other elements (expression, if, while...)
def checkBlockStatement(step):
    #TODO
    print("TODO")
