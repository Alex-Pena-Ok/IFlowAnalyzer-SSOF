from Expressions import executeAssignment, executeCall, executeBinaryExpression


# Executes the program step by step
def checkSteps(programSteps, ctx):
    for step in programSteps:
        assignmentType = step["type"]
        assignmentTypes[assignmentType](step, ctx)  # The return of a callExecution is ignorable in this case,
        # because it's not saved to any variable


# Executes an ExpressionStatement, assignments or function call's
def checkExpressionStatement(step, ctx):
    expression = step["expression"]
    expressionType = expression["type"]
    expressionTypes[expressionType](expression, ctx)


# Executes an IfStatement, binary expressions
def checkIfStatement(step, ctx):
    test = step["test"]
    testType = test["type"]
    ctx.taint = expressionTypes[testType](test, ctx)

    blockTrue = step["consequent"]
    checkBlockStatement(blockTrue, ctx)

    blockFalse = step["alternate"]
    if blockFalse is not None:
        checkBlockStatement(blockFalse, ctx)


# Executes a WhileStatement
def checkWhileStatement(step, ctx):
    test = step["test"]
    testType = test["type"]
    ctx.taint = expressionTypes[testType](test, ctx)

    block = step["body"]
    checkBlockStatement(block, ctx)


# Executes a BlockStatement, called by while & if's, can have any of the other elements (expression, if, while...)
# Pass the taint value of the conditional through the Context variable
def checkBlockStatement(step, ctx):
    block = step["body"]
    checkSteps(block, ctx)

    #TODO
    ctx.taint = False


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
    'WhileStatement': checkWhileStatement,
    'BlockStatement': checkBlockStatement
}
