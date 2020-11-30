
class Variable:
    def __init__(self, name, tainted, source):
        self.name = name
        self.tainted = tainted  # If tainted = true
        self.source = source    # Origin of the variable

    def getName(self):
        return self.name

    def getSource(self):
        return self.source

    def setTainted(self, tainted):
        self.tainted = tainted

    def getTainted(self):
        return self.tainted

    def setSource(self, source):
        self.source = source