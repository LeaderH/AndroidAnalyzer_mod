import util.log

name = "Test"
description = "Test"
result = {}
def getName():
    #"return analysis name"
    return name

def getDescription():
    #"return analysis description"
    return description

def getResults(results):
    results["Costom Test"] = result
    return results

def run(classes, dependencies, sharedobjs):
    pass