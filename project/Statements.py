from Expressions import executeAssignment, executeCall, executeBinaryExpression

# Dictionary to map between the expression type and the actual function to call
expressionTypes = {
    'AssignmentExpression': executeAssignment,
    'CallExpression': executeCall,
    'BinaryExpression': executeBinaryExpression
}


# Executes an ExpressionStatement, assignments or function call's
def checkExpressionStatement(step, ctx):
    expression = step["expression"]
    expressionType = expression["type"]
    expressionTypes[expressionType](expression, ctx)


# Executes an IfStatement, binary expressions
def checkIfStatement(step, ctx):
    #TODO
    print("TODO")


# Executes a WhileStatement
def checkWhileStatement(step, ctx):
    #TODO
    print("TODO")


# Executes a BlockStatement, called by while & if's, can have any of the other elements (expression, if, while...)
def checkBlockStatement(step, ctx):
    #TODO
    print("TODO")
