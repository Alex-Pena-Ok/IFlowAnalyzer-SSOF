from copy import deepcopy

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

    # Checks if the test is using or produces any tainted variable
    ctx.taint = expressionTypes[testType](test, ctx)

    # Different contexts are used below because if the same context was used
    # the values of the variables would collide and provide incorrect values eventually

    # Executes the if block
    consequentBlock = step["consequent"]
    new_ctx_consequent = deepcopy(ctx)
    checkBlockStatement(consequentBlock, new_ctx_consequent)

    # Executes the else block, if there is any
    alternateBlock = step["alternate"]
    new_ctx_alternate = None
    if alternateBlock is not None:
        new_ctx_alternate = deepcopy(ctx)
        checkBlockStatement(alternateBlock, new_ctx_alternate)

    # Merge the contexts
    ctx.mergeContexts(new_ctx_consequent, new_ctx_alternate)
    return


# Executes a WhileStatement
def checkWhileStatement(step, ctx):
    test = step["test"]
    testType = test["type"]
    ctx.taint = expressionTypes[testType](test, ctx)

    block = step["body"]
    new_ctx_consequent = deepcopy(ctx)

    checkBlockStatement(block, new_ctx_consequent)
    ctx.mergeContexts(new_ctx_consequent, None)
    return


# Executes a BlockStatement, called by while & if's, can have any of the other elements (expression, if, while...)
# Pass the taint value of the conditional through the Context variable
def checkBlockStatement(step, ctx):
    block = step["body"]
    checkSteps(block, ctx)


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
