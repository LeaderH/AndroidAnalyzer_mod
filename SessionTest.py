from androguard import misc
from androguard import session
from util.analysisUtil import *
from util.analysisConst import *
import os
import os.path
import sys   
sys.setrecursionlimit(1000000)

if __name__ == "__main__":
    args = parseArgument()

    APK_FILE_NAME_STRING = DIRECTORY_APK_FILES + args.apk_file


    md5, sha1, sha256, sha512 = get_hashes_by_filename(APK_FILE_NAME_STRING)
    
    sessionFile = str(md5)

    if os.path.isfile(sessionFile) and os.access(sessionFile, os.R_OK):
        print("Loading session file at " + str(sessionFile) + ", please wait... \n")
        sess = session.Load(str(sessionFile))
        a, d, dx=sess.get_objects_apk(APK_FILE_NAME_STRING)

    else:
        print("No session file found, creating one! Please wait...")
        # get a default session
        sess = misc.get_default_session()
        # Use the session
        a, d, dx = misc.AnalyzeAPK(APK_FILE_NAME_STRING, session=sess)
        # Save the session to disk
        session.Save(sess, str(md5))
    print(a.get_permissions())
'''
Result: Not faster
'''