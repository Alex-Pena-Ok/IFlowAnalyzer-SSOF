from Statements import checkSteps
from Context import Context


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
