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

    # Check if the CallExpression callee is a sink, in this
    # case the parameter it receives matters.
    vulnName = ctx.searchInVulnPattern(functionName, SINKS)
    if vulnName != "":
        # Check if the CallExpression callee argument is tainted
        for argument in arguments:
            #TODO: Argument is another function: f(a())

            # Argument is a binary expression : a+b
            argType = argument["type"]
            if argType == "BinaryExpression":
                source = binaryExpression(argument, ctx)
                if source != "":
                    # The sink is going to use a TAINTED variable
                    vuln = ctx.createVulnerability(vulnName, source, functionName)
                    ctx.addVulnerability(vuln)
                    return sinkFunc()
                else:
                    continue

            # Argument is a single variable: a
            if argType == "Identifier":
                if ctx.checkVariable(argument["name"]):  # Variable is TAINTED, vulnerability detected
                    vuln = ctx.createVulnerability(vulnName, ctx.getSource(argument["name"]), functionName, argument["name"])
                    ctx.addVulnerability(vuln)
                    return sinkFunc()


    # It's not a sanitizer, sink or source... (any possible function)
    #TODO: If its not sanitizer, sink or source and its another nested function, the nested function must be checked too
    # recursivamente call function?
    return False


# Returns true if any of the arguments involved are a sink using tainted variables
# or tainted variable.
# Inside a member expression can be multiple member expressions or function call's.
# e.g. f=e(c+"oi"+d+"hi"+h(),g);
# TODO: Function calls inside member expressions
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
            sourceFunc = lambda _: False
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

