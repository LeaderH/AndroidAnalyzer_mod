
from util.analysisUtil import *
from util.analysisConst import *
import util.pluginLoader as pluginLoader
import util.log
import time
import re
from datetime import datetime
from zipfile import BadZipfile
#from tools.modified.androguard.core.bytecodes import apk
#from tools.modified.androguard.core.bytecodes import dvm
#from tools.modified.androguard.core.analysis import analysis
#from tools.modified.androguard.core import bytecode
import androguard.misc


import lint_checks

logger = util.log.Logger('Analyze.log',util.log.WARNING,util.log.DEBUG)

def __analyze(writer, args) :
    """
        Exception:
            apk_file_not_exist
            classes_dex_not_in_apk
    """
    #StopWatch: Counting execution time...
    stopwatch_start = datetime.now()

    if args.line_max_output_characters is None :
        if platform.system().lower() == "windows" :
            args.line_max_output_characters = LINE_MAX_OUTPUT_CHARACTERS_WINDOWS - LINE_MAX_OUTPUT_INDENT
        else :
            args.line_max_output_characters = LINE_MAX_OUTPUT_CHARACTERS_LINUX - LINE_MAX_OUTPUT_INDENT

    if not os.path.isdir(args.report_output_dir) :
        os.mkdir(args.report_output_dir)

    writer.writeInf_ForceNoPrint("analyze_mode", args.analyze_mode)
    writer.writeInf_ForceNoPrint("analyze_engine_build", args.analyze_engine_build)
    if args.analyze_tag :
        writer.writeInf_ForceNoPrint("analyze_tag", args.analyze_tag)

    APK_FILE_NAME_STRING = DIRECTORY_APK_FILES + args.apk_file
    apk_Path = APK_FILE_NAME_STRING  # + ".apk"

    if (".." in args.apk_file) :
        raise ExpectedException("apk_file_name_slash_twodots_error", "APK file name should not contain slash(/) or two dots(..) (File: " + apk_Path + ").") 

    if not os.path.isfile(apk_Path) :
        raise ExpectedException("apk_file_not_exist", "APK file not exist (File: " + apk_Path + ").")
    
    if args.store_analysis_result_in_db :
        try:
            imp.find_module('pymongo')
            found_pymongo_lib = True
        except importerror:
            found_pymongo_lib = False

        if not found_pymongo_lib :
            pass
    

    #apk_filepath_relative = apk_Path
    apk_filepath_absolute = os.path.abspath(apk_Path)

    #writer.writeInf_ForceNoPrint("apk_filepath_relative", apk_filepath_relative)
    writer.writeInf_ForceNoPrint("apk_filepath_absolute", apk_filepath_absolute)

    apk_file_size = float(os.path.getsize(apk_filepath_absolute)) / (1024 * 1024) #in KB
    writer.writeInf_ForceNoPrint("apk_file_size", apk_file_size)

    writer.update_analyze_status("loading_apk")

    writer.writeInf_ForceNoPrint("time_starting_analyze", datetime.utcnow())

    a, dexs, vmx = androguard.misc.AnalyzeAPK(APK_FILE_NAME_STRING) #Time consuming

    writer.update_analyze_status("starting_apk")

    package_name = a.get_package()

    if isNullOrEmptyString(package_name, True) :
        raise ExpectedException("package_name_empty", "Package name is empty (File: " + apk_Path + ").")

    writer.writeInf("platform", "Android", "Platform")
    writer.writeInf("package_name", str(package_name), "Package Name")

    # Check: http://developer.android.com/guide/topics/manifest/manifest-element.html
    if not isNullOrEmptyString(a.get_androidversion_name()):
        try :
            writer.writeInf("package_version_name", str(a.get_androidversion_name()), "Package Version Name")
        except :
            writer.writeInf("package_version_name", a.get_androidversion_name().encode('ascii', 'ignore'), "Package Version Name")

    if not isNullOrEmptyString(a.get_androidversion_code()):
        # The version number shown to users. This attribute can be set as a raw string or as a reference to a string resource. 
        # The string has no other purpose than to be displayed to users. 
        try :
            writer.writeInf("package_version_code", int(a.get_androidversion_code()), "Package Version Code")
        except ValueError :
            writer.writeInf("package_version_code", a.get_androidversion_code(), "Package Version Code")

    if len(a.get_dex()) == 0:
        raise ExpectedException("classes_dex_not_in_apk", "Broken APK file. \"classes.dex\" file not found (File: " + apk_Path + ").")

    try:
        str_min_sdk_version = a.get_min_sdk_version()
        if (str_min_sdk_version is None) or (str_min_sdk_version == "") :
            raise ValueError
        else:
            int_min_sdk = int(str_min_sdk_version)
            writer.writeInf("minSdk", int_min_sdk, "Min Sdk")
    except ValueError:
        # Check: http://developer.android.com/guide/topics/manifest/uses-sdk-element.html
        # If "minSdk" is not set, the default value is "1"
        writer.writeInf("minSdk", 1, "Min Sdk")
        int_min_sdk = 1

    try:
        str_target_sdk_version = a.get_target_sdk_version()
        if (str_target_sdk_version is None) or (str_target_sdk_version == "") :
            raise ValueError
        else:
            int_target_sdk = int(str_target_sdk_version)
            writer.writeInf("targetSdk", int_target_sdk, "Target Sdk")
    except ValueError:
        # Check: http://developer.android.com/guide/topics/manifest/uses-sdk-element.html
        # If not set, the default value equals that given to minSdkVersion.
        int_target_sdk = int_min_sdk

    md5, sha1, sha256, sha512 = get_hashes_by_filename(APK_FILE_NAME_STRING)
    writer.writeInf("file_md5", md5, "MD5   ")
    writer.writeInf("file_sha1", sha1, "SHA1  ")
    writer.writeInf("file_sha256", sha256, "SHA256")
    writer.writeInf("file_sha512", sha512, "SHA512")

    writer.update_analyze_status("starting_dvm")

    d=None
    if len(dexs)>0:
        d=dexs[0];
        pass #MasterKey >1

    writer.update_analyze_status("start")

    analyze_start = datetime.now()

    # ////////////////////////////////////////////////////////////////////////////////////////////////////////////


    pluginLoader.runPlugins(a,d,vmx,writer);
 
    #--------------------------------------------------------------------

    #----------------------------------------------------------------
    #Must complete the last writer

    writer.completeWriter()

    writer.writeInf_ForceNoPrint("vector_total_count", writer.get_total_vector_count())

    #----------------------------------------------------------------
    #End of Checking

    #StopWatch
    now = datetime.now()
    stopwatch_total_elapsed_time = now - stopwatch_start
    stopwatch_analyze_time = now - analyze_start 
    stopwatch_loading_vm = analyze_start - stopwatch_start

    writer.writeInf_ForceNoPrint("time_total", stopwatch_total_elapsed_time.total_seconds())
    writer.writeInf_ForceNoPrint("time_analyze", stopwatch_analyze_time.total_seconds())
    writer.writeInf_ForceNoPrint("time_loading_vm", stopwatch_loading_vm.total_seconds())

    writer.update_analyze_status("success")
    writer.writeInf_ForceNoPrint("time_finish_analyze", datetime.utcnow())

def main() :

    args = parseArgument()

    writer = Writer()

    try :

        #Print Title
        writer.writePlainInf(
"""
*************************************************************************
**                            version: 0.0.1                           **
*************************************************************************
""")
        #Analyze
        __analyze(writer, args)

        analyze_signature = get_hash_scanning(writer)
        writer.writeInf_ForceNoPrint("signature_unique_analyze", analyze_signature) #For uniquely distinguish the analysis report
        writer.append_to_file_io_information_output_list("Analyze Signature: " + analyze_signature)
        writer.append_to_file_io_information_output_list("------------------------------------------------------------------------------------------------")

    except ExpectedException as err_expected :

        writer.update_analyze_status("fail")

        writer.writeInf_ForceNoPrint("analyze_error_type_expected", True)
        writer.writeInf_ForceNoPrint("analyze_error_time", datetime.utcnow())
        writer.writeInf_ForceNoPrint("analyze_error_id", err_expected.get_err_id())
        writer.writeInf_ForceNoPrint("analyze_error_message", err_expected.get_err_message())

        writer.writeInf_ForceNoPrint("signature_unique_analyze", get_hash_scanning(writer)) #For uniquely distinguish the analysis report
        writer.writeInf_ForceNoPrint("signature_unique_exception", get_hash_exception(writer))

        if DEBUG :
            print(err_expected)

    except BadZipfile as zip_err :  #This may happen in the "a = apk.APK(apk_Path)"

        writer.update_analyze_status("fail")

        #Save the fail message to db
        writer.writeInf_ForceNoPrint("analyze_error_detail_traceback", traceback.format_exc())

        writer.writeInf_ForceNoPrint("analyze_error_type_expected", True)
        writer.writeInf_ForceNoPrint("analyze_error_time", datetime.utcnow())
        writer.writeInf_ForceNoPrint("analyze_error_id", "fail_to_unzip_apk_file")
        writer.writeInf_ForceNoPrint("analyze_error_message", str(zip_err))

        writer.writeInf_ForceNoPrint("signature_unique_analyze", get_hash_scanning(writer))     #For uniquely distinguish the analysis report
        writer.writeInf_ForceNoPrint("signature_unique_exception", get_hash_exception(writer))

        if DEBUG :
            print("[Unzip Error]")
            traceback.print_exc()

    except Exception as err :

        writer.update_analyze_status("fail")

        #Save the fail message to db
        writer.writeInf_ForceNoPrint("analyze_error_detail_traceback", traceback.format_exc())

        writer.writeInf_ForceNoPrint("analyze_error_type_expected", False)
        writer.writeInf_ForceNoPrint("analyze_error_time", datetime.utcnow())
        writer.writeInf_ForceNoPrint("analyze_error_id", str(type(err)))
        writer.writeInf_ForceNoPrint("analyze_error_message", str(err))

        writer.writeInf_ForceNoPrint("signature_unique_analyze", get_hash_scanning(writer)) #For uniquely distinguish the analysis report
        writer.writeInf_ForceNoPrint("signature_unique_exception", get_hash_exception(writer))

        if DEBUG :
            traceback.print_exc()

    #Save to the DB
    if args.store_analysis_result_in_db :
        __persist_db(writer, args)


    if writer.get_analyze_status() == "success" :

        if REPORT_OUTPUT == TYPE_REPORT_OUTPUT_ONLY_PRINT :
            writer.show(args)
        elif REPORT_OUTPUT == TYPE_REPORT_OUTPUT_ONLY_FILE :
            __persist_file(writer, args)    #write report to "disk"
        elif REPORT_OUTPUT == TYPE_REPORT_OUTPUT_PRINT_AND_FILE :
            writer.show(args)
            __persist_file(writer, args)    #write report to "disk"

def __persist_db(writer, args) :
    
    # starting_dvm
    # starting_androbugs

    if platform.system().lower() == "windows" :
        db_config_file = os.path.join(os.path.dirname(sys.executable), 'androbugs-db.cfg')
    else :
        db_config_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'androbugs-db.cfg')

    if not os.path.isfile(db_config_file) :
        print("[ERROR] AndroBugs Framework DB config file not found: " + db_config_file)
        traceback.print_exc()

    configParser = SafeConfigParser()
    configParser.read(db_config_file)

    MongoDB_Hostname = configParser.get('DB_Config', 'MongoDB_Hostname')
    MongoDB_Port = configParser.getint('DB_Config', 'MongoDB_Port')
    MongoDB_Database = configParser.get('DB_Config', 'MongoDB_Database')

    Collection_Analyze_Result = configParser.get('DB_Collections', 'Collection_Analyze_Result')
    Collection_Analyze_Success_Results = configParser.get('DB_Collections', 'Collection_Analyze_Success_Results')
    Collection_Analyze_Success_Results_FastSearch = configParser.get('DB_Collections', 'Collection_Analyze_Success_Results_FastSearch')
    Collection_Analyze_Fail_Results = configParser.get('DB_Collections', 'Collection_Analyze_Fail_Results')

    from pymongo import MongoClient
    client = MongoClient(MongoDB_Hostname, MongoDB_Port)
    db = client[MongoDB_Database]   # Name is case-sensitive

    analyze_status = writer.get_analyze_status()

    try :

        if analyze_status is not None :
            #You might not get Package name when in "starting_apk" stage

            packed_analyzed_results = writer.get_packed_analyzed_results_for_mongodb()  # "details" will only be shown when success
            packed_analyzed_results_fast_search = writer.get_search_enhanced_packed_analyzed_results_for_mongodb()  # specifically designed for Massive Analysis

            collection_AppInfo = db[Collection_Analyze_Result]      # Name is case-sensitive
            collection_AppInfo.insert(packed_analyzed_results)
            
            if analyze_status == "success" :    #save analyze result only when successful
                collection_AnalyzeSuccessResults = db[Collection_Analyze_Success_Results]
                collection_AnalyzeSuccessResults.insert(packed_analyzed_results)

                collection_AnalyzeSuccessResultsFastSearch = db[Collection_Analyze_Success_Results_FastSearch]
                collection_AnalyzeSuccessResultsFastSearch.insert(packed_analyzed_results_fast_search)

        if (analyze_status == "fail") :
            collection_AnalyzeExceptions = db[Collection_Analyze_Fail_Results]      # Name is case-sensitive
            collection_AnalyzeExceptions.insert(writer.getInf())

    # pymongo.errors.BulkWriteError, pymongo.errors.CollectionInvalid, pymongo.errors.CursorNotFound, pymongo.errors.DocumentTooLarge, pymongo.errors.DuplicateKeyError, pymongo.errors.InvalidOperation
    except Exception as err:
        try :
            writer.update_analyze_status("fail")
            writer.writeInf_ForceNoPrint("analyze_error_detail_traceback", traceback.format_exc())

            writer.writeInf_ForceNoPrint("analyze_error_type_expected", False)
            writer.writeInf_ForceNoPrint("analyze_error_time", datetime.utcnow())
            writer.writeInf_ForceNoPrint("analyze_error_id", str(type(err)))
            writer.writeInf_ForceNoPrint("analyze_error_message", str(err))

            packed_analyzed_results = writer.getInf()
            """
                http://stackoverflow.com/questions/5713218/best-method-to-delete-an-item-from-a-dict
                There's also the minor point that .pop will be slightly slower than the del since it'll translate to a function call rather than a primitive.
                packed_analyzed_results.pop("details", None)    #remove the "details" tag, if the key is not found => return "None"
            """
            if "details" in packed_analyzed_results :   #remove "details" result to prevent the issue is generating by the this item
                del packed_analyzed_results["details"]

            collection_AnalyzeExceptions = db[Collection_Analyze_Fail_Results]      # Name is case-sensitive
            collection_AnalyzeExceptions.insert(packed_analyzed_results)
        except :
            if DEBUG :
                print("[Error on writing Exception to MongoDB]")
                traceback.print_exc()

def __persist_file(writer, args) :

    package_name =  writer.getInf("package_name")
    signature_unique_analyze =  writer.getInf("signature_unique_analyze")

    if package_name and signature_unique_analyze :
        return writer.save_result_to_file(os.path.join(args.report_output_dir, package_name + "_" + signature_unique_analyze + ".txt"), args)
    else :
        print("\"package_name\" or \"signature_unique_analyze\" not exist.")
        return False

if __name__ == "__main__":
    main()
