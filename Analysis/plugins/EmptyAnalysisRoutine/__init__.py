__author__ = 'Matt Clarke-Lauer'
__email__ = 'matt@clarkelauer.com'
__credits__ = ['Matt Clarke-Lauer']
__date__ = 8 / 1 / 13

__version__ = '0.1'
__status__ = 'Development'

'''
Example analysis
'''

name = "EmptyAnalysisRoutine"
description = "Does Nothing"
result = "No Results"

def getName():
    "return analysis name"
    return name

def getDescription():
    "return analysis description"
    return description

def getResults(results):
    "add result of analysis to result dictionary"
    #results["Empty Analysis"] = result
    return results

def run(classes, dependencies, sharedobjs):
    " run analysis routine "
    pass


