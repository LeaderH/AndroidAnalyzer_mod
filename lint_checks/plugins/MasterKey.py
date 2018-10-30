from util.analysisUtil import *
from util.analysisConst import *

name = "MASTER_KEY"
description = "Master Key Type I Vulnerability"
tags=None

def getName():
    #"return analysis name"
    return name

def getDescription():
    #"return analysis description"
    return description

def getTags():
    return tags

def run(a,d,vmx,writer):
    isMasterKeyVulnerability = False
    dexes_count = 0
    all_files = a.get_files()
    for f in all_files:
        if f == 'classes.dex':
            dexes_count += 1

    if dexes_count > 1:
        isMasterKeyVulnerability = True
        
    if isMasterKeyVulnerability :
        writer.startWriter(name, LEVEL_CRITICAL, description, \
            "This APK is suffered from Master Key Type I Vulnerability.", \
            tags, "CVE-2013-4787")
    else :
        writer.startWriter(name, LEVEL_INFO, description, \
            "No Master Key Type I Vulnerability in this APK.", \
            tags, "CVE-2013-4787")
