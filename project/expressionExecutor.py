from constants import SOURCES, SANITIZERS, SINKS


# TODO: BinaryExpressions & nested call's
def callExpression(functionName, ctx, sourceFunc, sanitizerFunc, sinkFunc, arguments):
    # Check if the CallExpression callee is a source
    # if it's a source, it's parameters don't really matter.
    if ctx.searchInVulnPattern(functionName, SOURCES) != "":
        return sourceFunc()

    # Check if the CallExpression calle is a sanitizer
    # I assumed here that the sanitizer returns a new sanitized variable
    # instead of 'sanitizing' the one passed to it as argument
    # therefore the old one keeps tainted.
    if ctx.searchInVulnPattern(functionName, SANITIZERS) != "":
        return sanitizerFunc()

    # At this point we know that the function is neither a SOURCE or a SANITIZER
    # it can still be a SINK, or another function that propagates ILLEGAL Information
    # Flows throught tainted variables.
    for argument in arguments:
        argType = argument["type"]

        # Literals are always safe
        if argType == "Literal":
            continue

        # Argument is another function, the 'callExpression' must then be
        # called recursively
        if argType == "CallExpression":
            # TODO: Argument is another function: f(a())
            nestedSourceFunc = lambda: True
            nestedSanitizerFunc = lambda: False
            nestedSinkFunc = lambda: True
            arguments = argument["arguments"]
            if callExpression(functionName, ctx, nestedSourceFunc, nestedSanitizerFunc, nestedSinkFunc, arguments):
                # Do something here
                continue

        # Argument is a binary expression : a+b | a + b()...
        if argType == "BinaryExpression":
            # Check if the CallExpression callee is a sink, in this
            # case the parameter it receives matters.
            vulnName = ctx.searchInVulnPattern(functionName, SINKS)
            if vulnName != "":
                source = binaryExpression(argument, ctx)
                if source != "":
                    # The sink is going to use a TAINTED variable
                    vuln = ctx.createVulnerability(vulnName, source, functionName)
                    ctx.addVulnerability(vuln)
                    return sinkFunc()
                else:
                    continue

        # Argument is an identifier (variable in this case)
        if argType == "Identifier":
            varName = argument["name"]
            if ctx.checkVariable(varName):  # Variable is TAINTED, vulnerability detected
                # Check if the CallExpression callee is a sink, if it is VULNERABILITY detected.
                # Otherwise propagate the tainted to the left assigned variable
                # (if its an assignment, otherwise is ignored)
                vulnName = ctx.searchInVulnPattern(functionName, SINKS)
                if vulnName != "":
                    vuln = ctx.createVulnerability(vulnName, varName, functionName)
                    ctx.addVulnerability(vuln)
                    return sinkFunc()
                else:   # Its not a sink, but its using a TAINTED variable, if its assignment type TAINT the left var
                    return sourceFunc(varName)

    return False


# Returns true if any of the arguments involved are a sink using tainted variables
# or tainted variable.
# Inside a member expression can be multiple member expressions or function call's.
# e.g. f=e(c+"oi"+d+"hi"+h(),g);
def binaryExpression(curr, ctx):
    currType = curr["type"]

    if currType != "BinaryExpression":
        if currType == "Literal":
            return ""   # Literals are always safe, no source
        elif currType == "Identifier":
            if ctx.checkVariable(curr["name"]):
                return ctx.getSource(curr["name"])  # The variable used is TAINTED return its source
            else:
                return ""  # The variable is UNTAINTED
        elif currType == "CallExpression": # TODO: And when CallExpression has to then call back another BinaryExpression? Jesus christ
            functionName = curr["callee"]["name"]
            sourceFunc = lambda _: True
            sanitizerFunc = lambda _: False
            sinkFunc = lambda _: True
            arguments = curr["arguments"]
            return callExpression(functionName, ctx, sourceFunc, sanitizerFunc, sinkFunc, arguments)

    # Recursively check LEFT side for TAINTED variables
    if curr["left"]["type"] is not None:
        left = curr["left"]
        source = binaryExpression(left, ctx)
        if source != "":
            return source

    # Recursively check RIGHT side for TAINTED variables
    if curr["right"]["type"] is not None:
        right = curr["right"]
        source = binaryExpression(right, ctx)
        if source != "":
            return source

    # No tainted variable found
    return ""

