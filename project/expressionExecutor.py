from constants import SOURCES, SANITIZERS, SINKS

sinkName = ""
sourceName = ""


# Execute the first level of a function call
def callExpression(functionName, ctx, arguments, sourceFunc=lambda _: True, sanitizerFunc=lambda: False, sinkFunc=lambda: True, defaultFunc=lambda: False):
    # Check if the CallExpression callee is a source
    # if it's a source, it's parameters don't really matter.
    if ctx.searchInVulnPattern(functionName, SOURCES) != "":
        return sourceFunc("")

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

        # Handles: a(b()) type of vulnerabilities
        if argType == "CallExpression":
            arguments = argument["arguments"]
            nestedFunctionName = argument["callee"]["name"]
            # If there is a vulnerability it will be created in the executeNestedCallExpression function,
            # and the return will be TRUE which means it is TAINTED and shall return
            # to inform the rest by calling sourceFunc().

            # Passing as last argument the name of the sink if the first function is a sink
            # or empty string if its not a sink
            global sinkName, sourceName
            sinkName = functionName if ctx.searchInVulnPattern(functionName, SINKS) != "" else ""

            if executeNestedCallExpression(nestedFunctionName, arguments, ctx):
                if sinkName != "":  # Currently inside a sink and using TAINTED variables, therefore its a VULNERABILITY
                    vulnName = ctx.searchInVulnPattern(sinkName, SINKS)
                    if vulnName != "":
                        vuln = ctx.createVulnerability(vulnName, sourceName, sinkName)
                        ctx.addVulnerability(vuln)
                return sourceFunc("")  # Only returns TRUE if the nested level right below the 1st is returning TAINTED

        # Handles: "a"+b() type of vulnerabilities
        if argType == "BinaryExpression":
            if not executeBinaryExpressionInCallExpression(functionName, argument, ctx, sinkFunc):
                continue

        # Handles: b(a) type of vulnerabilities
        if argType == "Identifier":
            varName = argument["name"]
            if executeIdentifierInCallExpression(functionName, varName, ctx, sourceFunc, sinkFunc):
                return True

    return defaultFunc()


#TODO: This function is probably unecessary, improve code
#
# Argument is a nested function, the 'callExpression' must then be
# called recursively. There is also no assignment in a nested function
# therefore we don't need to worry about adding a TAINTED variable.
#
# This function is extremely similar to the executeCallExpression, but the
# advantage is that offers a "new" context which facilitates operations
# regarding all possible combinations of nested functions.
def executeNestedCallExpression(nestedFunctionName, nestedArguments, ctx):
    global sinkName, sourceName
    sourceName = nestedFunctionName

    if ctx.searchInVulnPattern(nestedFunctionName, SOURCES) != "":
        return True

    if ctx.searchInVulnPattern(nestedFunctionName, SANITIZERS) != "":
        return False

    for argument in nestedArguments:
        argType = argument["type"]

        # Literals are always safe
        if argType == "Literal":
            return False

        if argType == "CallExpression":
            nestedNestedarguments = argument["arguments"]
            nestedNestedFunctionName = argument["callee"]["name"]

            if sinkName == "":
                sinkName = nestedFunctionName if ctx.searchInVulnPattern(nestedFunctionName, SINKS) != "" else ""

            if executeNestedCallExpression(nestedNestedFunctionName, nestedNestedarguments, ctx):
                return True
            else:
                # If it is returning false a sanitizer is in the way
                return False

        if argType == "BinaryExpression":
            if not executeBinaryExpressionInCallExpression(nestedFunctionName, argument, ctx, lambda: True):
                continue

        if argType == "Identifier":
            varName = argument["name"]
            return executeIdentifierInCallExpression(nestedFunctionName, varName, ctx, lambda: True, lambda: True)

    return False


# Argument is a binary expression : a+b | a + b()...
def executeBinaryExpressionInCallExpression(functionName, argument, ctx, sinkFunc):
    # Check if the CallExpression callee is a sink, in this
    # case the parameter it receives matters.
    vulnName = ctx.searchInVulnPattern(functionName, SINKS)
    if vulnName != "":
        # Runs the binary expression in search of TAINTED variables
        source = binaryExpression(argument, ctx)
        if source != "":
            # The sink is going to use a TAINTED variable
            vuln = ctx.createVulnerability(vulnName, source, functionName)
            ctx.addVulnerability(vuln)
            return sinkFunc()
        else:
            # The function is indeed a sink but there is no TAINTED variable
            # being used, therefore is safe.
            # And search must continue...
            return False


# Argument is an identifier (variable in this case)
def executeIdentifierInCallExpression(functionName, varName, ctx, sourceFunc, sinkFunc):
    if ctx.checkVariable(varName):  # Variable is TAINTED, vulnerability detected
        # Check if the CallExpression callee is a sink, if it is VULNERABILITY detected.
        # Otherwise propagate the tainted to the left assigned variable
        # (if its an assignment, otherwise is ignored)
        vulnName = ctx.searchInVulnPattern(functionName, SINKS)
        if vulnName != "":
            vuln = ctx.createVulnerability(vulnName, varName, functionName)
            ctx.addVulnerability(vuln)
            return sinkFunc()
        else:  # Its not a sink, but its using a TAINTED variable, if its assignment type TAINT the left var
            return sourceFunc(varName)
    else:
        return False


# Returns the name of the source if any of the arguments involved are a sink using tainted variables
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
            arguments = curr["arguments"]
            return callExpression(functionName, ctx, arguments)

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

