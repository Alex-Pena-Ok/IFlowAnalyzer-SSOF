
class Variable:
    def __init__(self, name, tainted):
        self.name = name
        self.tainted = tainted  # If tainted = true
