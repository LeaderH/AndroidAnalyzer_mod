
import log
from Analysis import analysisUtils

name = "customTest"
description = "customTest"
result = {}

def getName():
    "return analysis name"
    return name

def getDescription():
    "return analysis description"
    return description

def getResults(results):
    results["Costom Test"] = result
    return results

def run(classes, dependencies, sharedobjs):
    #TODO : look for bouncycastle and different encryption standards
    global result
    #log.info("Analysis: Java Crypto Libs")
    result["Costom properties"] = False
    
    for cl in classes:
        for meth in classes[cl]['Methods']:
            for invocations in meth['Invokes']:
                if "init" in invocations['Function']:
                    result["Costom properties"] = True
    #print dependencies
    # for d in dependencies["internal"]:
        # print d
    # for d in dependencies["external"]:
        # if d.startswith("javax/crypto"):
            # result["Depends on JavaX Crypto"] = True
        # if d.startswith("spongycastle"):
            # result["Depends on Spongycastle"] = True

    #result["Deep Analysis"]= analysisUtils.findObjects(classes,"javax/crypto")
