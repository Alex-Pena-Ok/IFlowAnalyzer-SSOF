from Expressions import executeAssignment, executeCall, executeBinaryExpression

# Dictionary to map between the expression type and the actual function to call
expressionTypes = {
    'AssignmentExpression': executeAssignment,
    'CallExpression': executeCall,
    'BinaryExpression': executeBinaryExpression
}

# Dictionary to map between the statement type and the actual function to call
assignmentTypes = {
    'ExpressionStatement': checkExpressionStatement,
    'IfStatement': checkIfStatement,
    'WhileStatement': checkWhileStatement
}

# Executes an ExpressionStatement, assignments or function call's
def checkExpressionStatement(step, ctx):
    expression = step["expression"]
    expressionType = expression["type"]
    expressionTypes[expressionType](expression, ctx)

# Executes an IfStatement, binary expressions
def checkIfStatement(step, ctx):
    test = step["test"]
    testType = test["type"]
    ctx.taint = expressionTypes[testType](test)

    block = step["consequent"]
    checkBlockStatement(block, ctx)

# Executes a WhileStatement
def checkWhileStatement(step, ctx):
    test = step["test"]
    testType = test["type"]
    ctx.taint = expressionTypes[testType](test)

    block = step["consequent"]
    checkBlockStatement(block, ctx)

# Executes a BlockStatement, called by while & if's, can have any of the other elements (expression, if, while...)
# Pass the taint value of the conditional through the Context variable
def checkBlockStatement(step, ctx):
    block = step["body"]
    for step in block:
        assignmentType = step["type"]
        assignmentTypes[assignmentType](step, ctx)
    ctx.taint = False
