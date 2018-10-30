from util.analysisUtil import *
from util.analysisConst import *

name = "JSINTERFACE"
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
    F=False;
    if(int(a.get_min_sdk_version())>=17):
        F=False
    #Landroid/webkit/WebView;->addJavascriptInterface(Ljava/lang/Object;Ljava/lang/String;)V
    debuggable = a.get_element("application", "debuggable")  #Check 'android:debuggable'
    if debuggable is not None and debuggable.lower() == 'true':
        writer.startWriter(name, LEVEL_CRITICAL, description, 
            "DEBUG mode is ON(android:debuggable=\"true\") in AndroidManifest.xml. This is very dangerous. The attackers will be able to sniffer the debug messages by Logcat. Please disable the DEBUG mode if it is a released application.", tags)
    else:
        writer.startWriter(name, LEVEL_INFO, description, "DEBUG mode is OFF(android:debuggable=\"false\") in AndroidManifest.xml.", tags)
        