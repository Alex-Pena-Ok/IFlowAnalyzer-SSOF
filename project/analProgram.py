from Context import Context
from Statements import checkExpressionStatement, checkBlockStatement, checkWhileStatement, checkIfStatement


# Dictionary to map between the statement type and the actual function to call
assignmentTypes = {
    'ExpressionStatement': checkExpressionStatement,
    'IfStatement': checkIfStatement,
    'WhileStatement': checkWhileStatement,
    'BlockStatement': checkBlockStatement
}


def analyzeProgram(programJson, vulnPattern):
    # Initializes object context, used to hold the state of the program during execution
    ctx = Context()

    # Extracts the vulnerabilities in the file pattern
    ctx.initVulnPattern(vulnPattern)

    # Analyzes program
    programSteps = programJson["body"]
    checkSteps(programSteps, ctx)

    # Concludes program execution
    ctx.writeOutput()


# Executes the program step by step
def checkSteps(programSteps, ctx):
    for step in programSteps:
        assignmentType = step["type"]
        assignmentTypes[assignmentType](step, ctx)
