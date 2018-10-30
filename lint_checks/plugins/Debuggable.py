from util.analysisUtil import *
from util.analysisConst import *

name = "DEBUGGABLE"
description = "Android Debug Mode Checking"
tags=["Debug"]

def getName():
    #"return analysis name"
    return name

def getDescription():
    #"return analysis description"
    return description

def getTags():
    return tags

def run(a,d,vmx,writer):
    debuggable = a.get_element("application", "debuggable")  #Check 'android:debuggable'
    if debuggable is not None and debuggable.lower() == 'true':
        writer.startWriter(name, LEVEL_CRITICAL, description, 
            "DEBUG mode is ON(android:debuggable=\"true\") in AndroidManifest.xml. This is very dangerous. The attackers will be able to sniffer the debug messages by Logcat. Please disable the DEBUG mode if it is a released application.", tags)
    else:
        writer.startWriter(name, LEVEL_INFO, description, "DEBUG mode is OFF(android:debuggable=\"false\") in AndroidManifest.xml.", tags)
        