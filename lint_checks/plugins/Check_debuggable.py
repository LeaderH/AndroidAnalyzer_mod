from util.analysisUtil import *
from util.analysisConst import *

name = "HACKER_DEBUGGABLE_CHECK"
description = "Codes for Checking Android Debug Mode"

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
        writer.startWriter(name, LEVEL_NOTICE, description, 
            "DEBUG mode is ON(android:debuggable=\"true\") in AndroidManifest.xml. This is very dangerous. The attackers will be able to sniffer the debug messages by Logcat. Please disable the DEBUG mode if it is a released application.", tags)
    else:
        writer.startWriter(name, LEVEL_INFO, description, "DEBUG mode is OFF(android:debuggable=\"false\") in AndroidManifest.xml.", tags)
  if list_detected_FLAG_DEBUGGABLE_path :
        writer.startWriter("HACKER_DEBUGGABLE_CHECK", LEVEL_NOTICE, "Codes for Checking Android Debug Mode", "Found codes for checking \"ApplicationInfo.FLAG_DEBUGGABLE\" in AndroidManifest.xml:", ["Debug", "Hacker"])

        for path in list_detected_FLAG_DEBUGGABLE_path:
            writer.show_single_PathVariable(d, path)
    else:
        writer.startWriter("HACKER_DEBUGGABLE_CHECK", LEVEL_INFO, "Codes for Checking Android Debug Mode", "Did not detect codes for checking \"ApplicationInfo.FLAG_DEBUGGABLE\" in AndroidManifest.xml.", ["Debug", "Hacker"])
      