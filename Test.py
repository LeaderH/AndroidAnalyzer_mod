#-*- coding: utf-8 -*-

from __future__ import division
from tools.modified.androguard.core.bytecodes import apk
from tools.modified.androguard.core.bytecodes import dvm
from tools.modified.androguard.core.analysis import analysis
from tools.modified.androguard.core import bytecode
import uuid
import os
import re
import time
from datetime import datetime
import hashlib    #sha256 hash
from textwrap import TextWrapper   #for indent in output
import base64
import collections  #for sorting key of dictionary
import traceback
import random
import argparse
from zipfile import BadZipfile
from ConfigParser import SafeConfigParser
import platform
import imp
import sys

"""
    *****************************************************************************
    ** AndroBugs Framework - Android App Security Vulnerability Scanner        **
    ** This tool is created by Yu-Cheng Lin (a.k.a. AndroBugs) @ AndroBugs.com **
    ** Twitter: @AndroBugs                                                     **
    ** Email: androbugs.framework@gmail.com                                    **
    *****************************************************************************

    ** Read Python codeing style first: http://www.python.org/dev/peps/pep-0008/ **

    1.This script run under Python 2.7. DO NOT use Python 3.x

    2.You need to install 'chilkat' component version in accordance with Python 2.7 first. This is for certificate checking.
      See the explanation of function 'def get_certificate(self, filename)' in 'apk.py' file
      => It becomes optional now. Since the related code is not comment out for ease of use and install.

    3.Use command 'grep -nFr "#Added by AndroBugs" *' to see what AndroBugs Framework has added to Androguard Open Source project under "tools/modified/androguard" root directory.

    4.Notice the "encoding" when copy and paste into this file (For example: the difference between single quote ' ).

    5.** Notice: In AndroidManifest.xml => The value "TRUE" or "True" or "true" are all the same (e.g. [android:exported="TRUE"] equals to [android:exported="true"]). 
      So if you want to check whether it is true, you should MAKE IT LOWER first. Otherwise, your code may have security issues. **

    Read these docs first:
        1.http://s.android.com/tech/dalvik/dex-format.html
        2.http://pallergabor.uw.hu/androidblog/dalvik_opcodes.html

    Provide the user the options:
        1.Specify the excluded package name (ex: Facebook.com, Parse.com) and put it into "STR_REGEXP_TYPE_EXCLUDE_CLASSES"
        2.Show the "HTTP Connection" related code or not
        3.Show the "KeyStore" related code or not

    Flag:
        [Critical] => very critical
        [Warning]  => it's ok and not really need to change
        [Notice]   => For hackers, you should notice.
        [Info]     => Information

    You can use these functions provided by the FilteringEngine to exclude class packages:
        (1)Filter single class name:
            is_class_name_not_in_exclusion(single_class_name_string)

        (2)Filter a list of class name:
            filter_list_of_classes(class_name_list)

        (3)Filter a list of method name:
            filter_list_of_methods(method_list)

        (4)Filter a list of Path:
            filter_list_of_paths(d, path_list)  #a list of PathP

        (5)Filter a list of Variables: #variables_list example: None or [[('R', 166), 5058]] or [[('R', 8), 5050], [('R', 24), 5046]]
            filter_list_of_variables(d, variables_list)   

        (6)Filter dictionary key classes: (filter the class names in the key)
            (boolean) is_all_of_key_class_in_dict_not_in_exclusion(key)

        (7) ...

    Current self-defined error id:
         - fail_to_unzip_apk_file
         - apk_file_name_slash_twodots_error
         - apk_file_not_exist
         - package_name_empty
         - classes_dex_not_in_apk

         search the corresponding error by using MongoDB criteria " {"analyze_error_id":"[error_id]"} "

    AndroBugs Framework is supported with MongoDB. Add "-s" argument if you want all the analysis results to be stored into the MongoDB.
    Please check the "androbugs-db.cfg" file for database configuration.

"""

#Fix settings:

TYPE_REPORT_OUTPUT_ONLY_PRINT = "print"
TYPE_REPORT_OUTPUT_ONLY_FILE = "file"
TYPE_REPORT_OUTPUT_PRINT_AND_FILE = "print_and_file"

TYPE_COMPARE_ALL = 1
TYPE_COMPARE_ANY = 2

ANALYZE_MODE_SINGLE = "single"
ANALYZE_MODE_MASSIVE = "massive"

#AndroidManifest permission protectionLevel constants
PROTECTION_NORMAL = 0   # "normal" or not set
PROTECTION_DANGEROUS = 1
PROTECTION_SIGNATURE = 2
PROTECTION_SIGNATURE_OR_SYSTEM = 3
PROTECTION_MASK_BASE = 15
PROTECTION_FLAG_SYSTEM = 16
PROTECTION_FLAG_DEVELOPMENT = 32
PROTECTION_MASK_FLAGS = 240

LEVEL_CRITICAL = "Critical"
LEVEL_WARNING = "Warning"
LEVEL_NOTICE = "Notice"
LEVEL_INFO = "Info"

LINE_MAX_OUTPUT_CHARACTERS_WINDOWS = 160  #100
LINE_MAX_OUTPUT_CHARACTERS_LINUX = 160
LINE_MAX_OUTPUT_INDENT = 20
#-----------------------------------------------------------------------------------------------------

#Customized settings:

DEBUG = True
ANALYZE_ENGINE_BUILD_DEFAULT = 1    # Analyze Engine(use only number)

DIRECTORY_APK_FILES = ""  # "APKs/"

REPORT_OUTPUT = TYPE_REPORT_OUTPUT_PRINT_AND_FILE  #when compiling to Windows executable, switch to "TYPE_REPORT_OUTPUT_ONLY_FILE"
DIRECTORY_REPORT_OUTPUT = "Reports/"    #Only need to specify when (REPORT_OUTPUT = TYPE_REPORT_OUTPUT_ONLY_FILE) or (REPORT_OUTPUT = TYPE_REPORT_OUTPUT_PRINT_AND_FILE)
# DIRECTORY_REPORT_OUTPUT = "Massive_Reports/"

#-----------------------------------------------------------------------------------------------------
"""
Package for exclusion:
Lcom/google/
Lcom/aviary/android/
Lcom/parse/
Lcom/facebook/
Lcom/tapjoy/
Lcom/android/
"""

#The exclusion list settings will be loaded into FilteringEngine later
STR_REGEXP_TYPE_EXCLUDE_CLASSES = "^(Landroid/support/|Lcom/actionbarsherlock/|Lorg/apache/)"
ENABLE_EXCLUDE_CLASSES = True

#-----------------------------------------------------------------------------------------------------

class Writer :

    def __init__(self) :
        self.__package_information = {}
        self.__cache_output_detail_stream = []
        self.__output_dict_vector_result_information = {}       # Store the result information (key: tag ; value: information_for_each_vector)
        self.__output_current_tag = ""                  #The current vector analyzed

        self.__file_io_result_output_list = []          #Analyze vector result (for more convenient to save in disk)
        self.__file_io_information_output_list = []     #Analyze header result (include package_name, md5, sha1, etc.)

    def simplifyClassPath(self, class_name) :
        if class_name.startswith('L') and class_name.endswith(';') :
            return class_name[1:-1]
        return class_name

    def show_Path(self, vm, path, indention_space_count=0) :
        """
            Different from analysis.show_Path, this "show_Path" writes to the tmp writer 
        """

        cm = vm.get_class_manager()

        if isinstance(path, analysis.PathVar):
            dst_class_name, dst_method_name, dst_descriptor =  path.get_dst( cm )
            info_var = path.get_var_info()

            self.write("=> %s (0x%x) ---> %s->%s%s" % (info_var,
                                                    path.get_idx(),
                                                    dst_class_name,
                                                    dst_method_name,
                                                    dst_descriptor),
                indention_space_count)

        else :
            if path.get_access_flag() == analysis.TAINTED_PACKAGE_CALL :
                src_class_name, src_method_name, src_descriptor =  path.get_src( cm )
                dst_class_name, dst_method_name, dst_descriptor =  path.get_dst( cm )

                self.write("=> %s->%s%s (0x%x) ---> %s->%s%s" % (src_class_name,
                                                                src_method_name,
                                                                src_descriptor,
                                                                path.get_idx(),
                                                                dst_class_name,
                                                                dst_method_name,
                                                                dst_descriptor),
                    indention_space_count)

            else :
                src_class_name, src_method_name, src_descriptor =  path.get_src( cm )

                self.write("=> %s->%s%s (0x%x)" % (src_class_name,
                                                src_method_name,
                                                src_descriptor,
                                                path.get_idx()),
                    indention_space_count)

    def show_Path_only_source(self, vm, path, indention_space_count=0) :
        cm = vm.get_class_manager()
        src_class_name, src_method_name, src_descriptor =  path.get_src( cm )
        self.write("=> %s->%s%s" % (src_class_name, src_method_name, src_descriptor), indention_space_count)        

    def show_Paths(self, vm, paths, indention_space_count=0) :
        """
            Show paths of packages
            :param paths: a list of :class:`PathP` objects

            Different from "analysis.show_Paths", this "show_Paths" writes to the tmp writer 
        """
        for path in paths :
            self.show_Path( vm, path, indention_space_count )

    def show_single_PathVariable(self, vm, path, indention_space_count=0):
        """
            Different from "analysis.show_single_PathVariable", this "show_single_PathVariable" writes to the tmp writer 

            method[0] : class name
            method[1] : function name
            method[2][0] + method[2][1]) : description
        """
        access, idx = path[0]
        m_idx = path[1]
        method = vm.get_cm_method(m_idx)

        self.write("=> %s->%s %s" % (method[0], method[1], method[2][0] + method[2][1]),    indention_space_count)

    #Output: stoping

    def startWriter(self, tag, level, summary, title_msg, special_tag=None, cve_number="") :    
        """
            "tag" is for internal usage
            "level, summary, title_msg, special_tag, cve_number" will be shown to the users
            It will be sorted by the "tag". The result will be sorted by the "tag".

            Notice: the type of "special_tag" is "list"
        """
        self.completeWriter()
        self.__output_current_tag = tag

        assert ((tag is not None) and (level is not None) and (summary is not None) and (title_msg is not None)), "\"tag\", \"level\", \"summary\", \"title_msg\" should all have it's value."

        if tag not in self.__output_dict_vector_result_information :
            self.__output_dict_vector_result_information[tag] = []

        dict_tmp_information = dict()
        dict_tmp_information["level"] = level
        dict_tmp_information["title"] = title_msg.rstrip('\n')
        dict_tmp_information["summary"] = summary.rstrip('\n')
        dict_tmp_information["count"] = 0
        if special_tag :
            assert isinstance(special_tag, list), "Tag [" + tag + "] : special_tag should be list"
            dict_tmp_information["special_tag"] = special_tag    #Notice: the type of "special_tag" is "list"
        if cve_number :
            assert isinstance(cve_number, basestring), "Tag [" + tag + "] : special_tag should be string"
            dict_tmp_information["cve_number"] = cve_number

        self.__output_dict_vector_result_information[tag] = dict_tmp_information
        
    def get_valid_encoding_utf8_string(self, utf8_string) :
        """
            unicode-escape: http://stackoverflow.com/questions/4004431/text-with-unicode-escape-sequences-to-unicode-in-python
            Encoding and Decoding:
                http://blog.wahahajk.com/2009/08/unicodedecodeerror-ascii-codec-cant.html
                http://www.evanjones.ca/python-utf8.html
                http://www.jb51.net/article/26543.htm
                http://www.jb51.net/article/17560.htm
        """
        return utf8_string.decode('unicode-escape').encode('utf8')

    def write(self, detail_msg, indention_space_count=0) :
        self.__cache_output_detail_stream.append(detail_msg + "\n")

    def get_packed_analyzed_results_for_mongodb(self) :
        # For external storage

        analyze_packed_result = self.getInf()

        if analyze_packed_result :
            if self.get_analyze_status() == "success" :
                analyze_packed_result["details"] = self.__output_dict_vector_result_information
            return analyze_packed_result

        return None

    def get_search_enhanced_packed_analyzed_results_for_mongodb(self) :
        # For external storage

        analyze_packed_result = self.getInf()

        if analyze_packed_result :
            if self.get_analyze_status() == "success" :

                prepared_search_enhanced_result = []

                for tag, dict_information in self.__output_dict_vector_result_information.items() :

                    search_enhanced_result = dict()

                    search_enhanced_result["vector"] = tag
                    search_enhanced_result["level"] = dict_information["level"]
                    search_enhanced_result["analyze_engine_build"] = analyze_packed_result["analyze_engine_build"]
                    search_enhanced_result["analyze_mode"] = analyze_packed_result["analyze_mode"]
                    if "analyze_tag" in analyze_packed_result :
                        search_enhanced_result["analyze_tag"] = analyze_packed_result["analyze_tag"]
                    search_enhanced_result["package_name"] = analyze_packed_result["package_name"]
                    if "package_version_code" in analyze_packed_result :
                        search_enhanced_result["package_version_code"] = analyze_packed_result["package_version_code"]
                    search_enhanced_result["file_sha512"] = analyze_packed_result["file_sha512"]
                    search_enhanced_result["signature_unique_analyze"] = analyze_packed_result["signature_unique_analyze"]
                    
                    prepared_search_enhanced_result.append(search_enhanced_result)

                return prepared_search_enhanced_result

        return None

    def getInf(self, key=None, default_value=None) :
        if key is None :
            return self.__package_information

        if key in self.__package_information :    
            value = self.__package_information[key]
            if (value is None) and (default_value is not None) :    # [Important] if default_value="", the result of the condition is "False"
                return default_value
            return value

        #not found
        if default_value :    # [Important] if default_value="", the result of the condition is "False"
            return default_value

        return None

    def writePlainInf(self, msg) :
        # if DEBUG :
        print(str(msg))
        # [Recorded here]
        self.__file_io_information_output_list.append(str(msg))

    def writeInf(self, key, value, extra_title, extra_print_original_title=False) :
        # if DEBUG :
        if extra_print_original_title :
            print(str(extra_title))
            # [Recorded here]
            self.__file_io_information_output_list.append(str(extra_title))
        else :
            print(extra_title + ": " + str(value))
            # [Recorded here]
            self.__file_io_information_output_list.append(extra_title + ": " + str(value))

        self.__package_information[key] = value

    def writeInf_ForceNoPrint(self, key, value) :
        self.__package_information[key] = value

    def update_analyze_status(self, status) :
        self.writeInf_ForceNoPrint("analyze_status", status)

    def get_analyze_status(self) :
        return self.getInf("analyze_status")

    def get_total_vector_count(self) :
        if self.__output_dict_vector_result_information :
            return len(self.__output_dict_vector_result_information)
        return 0

    def completeWriter(self) :
        # save to DB
        if (self.__cache_output_detail_stream) and (self.__output_current_tag != "") :   
            #This is the preferred way if you know that your variable is a string. If your variable could also be some other type then you should use myString == ""
            
            current_tag = self.__output_current_tag
            # try :
            if current_tag in self.__output_dict_vector_result_information :
                self.__output_dict_vector_result_information[current_tag]["count"] = len(self.__cache_output_detail_stream)

                """
                    Use xxx.encode('string_escape') to avoid translating user code into command
                    For example: regex in the code of users' applications may include "\n" but you should escape it.

                    I add "str(xxx)" because the "xxx" of xxx.encode should be string but "line" is not string.
                    Now the title and detail of the vectors are escaped(\n,...), so you need to use "get_valid_encoding_utf8_string"

                    [String Escape Example] 
                    http://stackoverflow.com/questions/6867588/how-to-convert-escaped-characters-in-python
                    >>> escaped_str = 'One \\\'example\\\''
                    >>> print escaped_str.encode('string_escape')
                    One \\\'example\\\'
                    >>> print escaped_str.decode('string_escape')
                    One 'example'
                """

                output_string = ""
                for line in self.__cache_output_detail_stream :
                    output_string = output_string + str(line).encode('string_escape')   # To escape the "\n" shown in the original string inside the APK

                self.__output_dict_vector_result_information[current_tag]["vector_details"] = self.get_valid_encoding_utf8_string(output_string.rstrip(str('\n').encode('string_escape')))
                try :
                    self.__output_dict_vector_result_information[current_tag]["title"] = self.get_valid_encoding_utf8_string(self.__output_dict_vector_result_information[current_tag]["title"])
                except KeyError :
                    if DEBUG:
                        print("[KeyError on \"self.__output_dict_vector_result_information\"]")
                    pass


        self.__output_current_tag = ""
        self.__cache_output_detail_stream[:] = []   # Clear the items in the list

    def is_dict_information_has_cve_number(self, dict_information) :
        if dict_information :
            if "cve_number" in dict_information :
                return True
        return False

    def is_dict_information_has_special_tag(self, dict_information) :
        if dict_information :
            if "special_tag" in dict_information :
                if dict_information["special_tag"] :
                    return True
        return False

    def __sort_by_level(key, value):
        try :
            level = value[1]["level"]

            if level == LEVEL_CRITICAL:
                return 5
            elif level == LEVEL_WARNING:
                return 4
            elif level == LEVEL_NOTICE:
                return 3
            elif level == LEVEL_INFO:
                return 2
            else:
                return 1
        except KeyError :
            return 1

    def append_to_file_io_information_output_list(self, line) :
        # Only write to the header of the "external" file
        self.__file_io_information_output_list.append(line)

    def save_result_to_file(self, output_file_path, args) :
        if not self.__file_io_result_output_list :
            self.load_to_output_list(args)

        try :
            with open(output_file_path, "w") as f :
                if self.__file_io_information_output_list :
                    for line in self.__file_io_information_output_list :
                        f.write(line + "\n")
                for line in self.__file_io_result_output_list :
                    f.write(line + "\n")

            print("<<< Analysis report is generated: " + os.path.abspath(output_file_path) + " >>>")
            print("")

            return True
        except IOError as err:
            if DEBUG :
                print("[Error on writing output file to disk]")
            return False

    def show(self, args) :
        if not self.__file_io_result_output_list :
            self.load_to_output_list(args)

        if self.__file_io_result_output_list :
            for line in self.__file_io_result_output_list :
                print(line)

    def output(self, line) :    #Store here for later use on "print()" or "with ... open ..."
        # [Recorded here]
        self.__file_io_result_output_list.append(line)

    def output_and_force_print_console(self, line) :    #Store here for later use on "print()" or "with ... open ..."
        # [Recorded here]
        self.__file_io_result_output_list.append(line)
        print(line)

    def load_to_output_list(self, args) :
        """
            tag => dict(level, title_msg, special_tag, cve_number)
            tag => list(detail output)
        
            print(self.__output_dict_vector_result_information)
            print(self.__output_dict_vector_result_information["vector_details"])

            Example output:
                {'WEBVIEW_RCE': {'special_tag': ['WebView', 'Remote Code Execution'], 'title': "...", 'cve_number': 'CVE-2013-4710', 'level': 'critical'}}
                "Lcom/android/mail/ui/ConversationViewFragment;->onCreateView(Landroid/view/LayoutInflater; Landroid/view/ViewGroup; 
                    Landroid/os/Bundle;)Landroid/view/View; (0xa4) ---> Lcom/android/mail/browse/ConversationWebView;->addJavascriptInterface(Ljava/lang/Object; Ljava/lang/String;)V"
        
            "vector_details" is a detail string of a vector separated by "\n" controlled by the users

        """

        self.__file_io_result_output_list[:] = []   #clear the list

        wrapperTitle = TextWrapper(initial_indent=' ' * 11, subsequent_indent=' ' * 11, width=args.line_max_output_characters)
        wrapperDetail = TextWrapper(initial_indent=' ' * 15, subsequent_indent=' ' * 20, width=args.line_max_output_characters)

        sorted_output_dict_result_information = collections.OrderedDict(sorted(self.__output_dict_vector_result_information.items()))   #Sort the dictionary by key

        for tag, dict_information in sorted(sorted_output_dict_result_information.items(), key=self.__sort_by_level, reverse=True) :    #Output the sorted dictionary by level
            extra_field = ""
            if self.is_dict_information_has_special_tag(dict_information) :
                for i in dict_information["special_tag"] :
                    extra_field += ("<" + i + ">")
            if self.is_dict_information_has_cve_number(dict_information) :
                extra_field += ("<#" + dict_information["cve_number"] + "#>")

            if args.show_vector_id :
                self.output("[%s] %s %s (Vector ID: %s):" % (dict_information["level"], extra_field, dict_information["summary"], tag))
            else :
                self.output("[%s] %s %s:" % (dict_information["level"], extra_field, dict_information["summary"]))

            for line in dict_information["title"].split('\n') :
                self.output(wrapperTitle.fill(line))

            if "vector_details" in dict_information :
                for line in dict_information["vector_details"].split('\n') :
                    self.output(wrapperDetail.fill(line))

        self.output("------------------------------------------------------------")

        stopwatch_total_elapsed_time = self.getInf("time_total")
        stopwatch_analyze_time = self.getInf("time_analyze")
        if stopwatch_total_elapsed_time and stopwatch_analyze_time :

            if (REPORT_OUTPUT == TYPE_REPORT_OUTPUT_ONLY_FILE) :
                self.output_and_force_print_console("AndroBugs analyzing time: " + str(stopwatch_analyze_time) + " secs")
                self.output_and_force_print_console("Total elapsed time: " + str(stopwatch_total_elapsed_time) + " secs")
            else:
                self.output("AndroBugs analyzing time: " + str(stopwatch_analyze_time) + " secs")
                self.output("Total elapsed time: " + str(stopwatch_total_elapsed_time) + " secs")

        if args.store_analysis_result_in_db :

            analysis_tips_output = "("

            if args.analyze_engine_build :
                analysis_tips_output += "analyze_engine_build: " + str(args.analyze_engine_build) + ", "

            if args.analyze_tag :
                analysis_tips_output += "analyze_tag: " + str(args.analyze_tag) + ", "

            if analysis_tips_output.endswith(", ") :
                analysis_tips_output = analysis_tips_output[:-2]

            analysis_tips_output += ")"

            if (REPORT_OUTPUT == TYPE_REPORT_OUTPUT_ONLY_FILE) :
                self.output_and_force_print_console("<<< Analysis result has stored into database " + analysis_tips_output + " >>>")
            else :
                self.output("<<< Analysis result has stored into database " + analysis_tips_output + " >>>")


class EfficientStringSearchEngine :

    """
        Usage:
            1.create an EfficientStringSearchEngine instance (only one should be enough)
            2.addSearchItem
            3.search
            4.get_search_result_by_match_id or get_search_result_dict_key_classname_value_methodlist_by_match_id
    """

    def __init__(self) :
        self.__prog_list = []
        self.__dict_result_identifier_to_search_result_list = {}

    def addSearchItem(self, match_id, search_regex_or_fix_string_condition, isRegex) :
        self.__prog_list.append( (match_id, search_regex_or_fix_string_condition, isRegex) )    # "root" checking

    def search(self, vm, allstrings_list) :
        
        """
            Example prog list input:
                [ ("match1", re.compile("PRAGMA\s*key\s*=", re.I), True), ("match2", re.compile("/system/bin/"), True), ("match3", "/system/bin/", False) ]

            Example return (Will always return the corresponding key, but the value is return only when getting the result):
                { "match1": [ (Complete_String_found, EncoddedMethod), (Complete_String_found, EncoddedMethod) ] , "match2": [] }
        """

        ## [String Search Performance Profiling]
        #string_finding_start = datetime.now()

        self.__dict_result_identifier_to_search_result_list.clear()

        for identifier, _ , _ in self.__prog_list : #initializing the return result list
            if identifier not in self.__dict_result_identifier_to_search_result_list :
                self.__dict_result_identifier_to_search_result_list[identifier] = []

        dict_string_value_to_idx_from_file_mapping = {}

        for idx_from_file, string_value in vm.get_all_offset_from_file_and_string_value_mapping() : #get a dictionary of string value and string idx mapping
            dict_string_value_to_idx_from_file_mapping[string_value] = idx_from_file

        ## [String Search Performance Profiling]
        #string_loading_end = datetime.now()
        #print("Time for loading String: " + str(((string_loading_end - string_finding_start).total_seconds())))

        list_strings_idx_to_find = []   #string idx list
        dict_string_idx_to_identifier = {}   # Example: (52368, "match1")

        #Get the searched strings into search idxs
        for line in allstrings_list :
            for identifier, regexp, isRegex in self.__prog_list :
                if (isRegex and regexp.search(line)) or ((not isRegex) and (regexp == line)) :
                    if line in dict_string_value_to_idx_from_file_mapping :   #Find idx by string
                        string_idx = dict_string_value_to_idx_from_file_mapping[line]
                        list_strings_idx_to_find.append(string_idx)
                        dict_string_idx_to_identifier[string_idx] = identifier

        list_strings_idx_to_find = set(list_strings_idx_to_find)    #strip duplicated items

        ## [String Search Performance Profiling]
        #string_finding_end = datetime.now()
        #print("Time for finding String: " + str((string_finding_end - string_finding_start).total_seconds()))

        if list_strings_idx_to_find :
            cm = vm.get_class_manager()
            for method in vm.get_methods() :
                for i in method.get_instructions():   # method.get_instructions(): Instruction
                    if (i.get_op_value() == 0x1A) or (i.get_op_value() == 0x1B) :  # 0x1A = "const-string", 0x1B = "const-string/jumbo"
                        ref_kind_idx = cm.get_offset_idx_by_from_file_top_idx(i.get_ref_kind())
                        if ref_kind_idx in list_strings_idx_to_find :  #find string_idx in string_idx_list
                            if ref_kind_idx in dict_string_idx_to_identifier :
                                original_identifier_name = dict_string_idx_to_identifier[ref_kind_idx]
                                self.__dict_result_identifier_to_search_result_list[original_identifier_name].append( (i.get_string(), method) )
        
        ## [String Search Performance Profiling]
        #elapsed_string_finding_time = datetime.now() - string_finding_start
        #print("String Search Elapsed time: " + str(elapsed_string_finding_time.total_seconds()))
        #print("------------------------------------------------------------")

        return self.__dict_result_identifier_to_search_result_list

    def get_search_result_by_match_id(self, match_id):
        return self.__dict_result_identifier_to_search_result_list[match_id]

    def get_search_result_dict_key_classname_value_methodlist_by_match_id(self, match_id):
        """
            Input: [ (Complete_String_found, EncoddedMethod), (Complete_String_found, EncoddedMethod) ] or []
            Output: dicionary key by class name
        """
        dict_result = {}

        search_result_value = self.__dict_result_identifier_to_search_result_list[match_id]

        try :
            if search_result_value :  #Found the corresponding url in the code
                result_list = set(search_result_value)

                for _ , result_method in result_list :  #strip duplicated item
                    class_name = result_method.get_class_name()
                    if class_name not in dict_result :
                        dict_result[class_name] = []

                    dict_result[class_name].append(result_method)
        except KeyError :
            pass

        return dict_result


class FilteringEngine :

    def __init__(self, enable_exclude_classes, str_regexp_type_excluded_classes) :
        self.__enable_exclude_classes = enable_exclude_classes
        self.__str_regexp_type_excluded_classes = str_regexp_type_excluded_classes
        self.__regexp_excluded_classes = re.compile(self.__str_regexp_type_excluded_classes, re.I)

    def get_filtering_regexp(self) :
        return self.__regexp_excluded_classes

    def filter_efficient_search_result_value(self, result) :

        if result is None :
            return []
        if (not self.__enable_exclude_classes) :
            return result

        l = []
        for found_string, method in result :
            if not self.__regexp_excluded_classes.match(method.get_class_name()) :
                l.append( (found_string, method) )

        return l

    def is_class_name_not_in_exclusion(self, class_name) :
        if self.__enable_exclude_classes :
            if self.__regexp_excluded_classes.match(class_name) :
                return False
            else :
                return True
        else :
            return True

    def is_all_of_key_class_in_dict_not_in_exclusion(self, dict_result) :
        if self.__enable_exclude_classes :
            isAllMatchExclusion = True
            for class_name, method_list in dict_result.items() :
                if not self.__regexp_excluded_classes.match(class_name) :   #any match
                    isAllMatchExclusion = False
            
            if isAllMatchExclusion :
                return False

            return True
        else :
            return True

    def filter_list_of_methods(self, method_list) :
        if self.__enable_exclude_classes and method_list :
            l = []
            for method in method_list :
                if not self.__regexp_excluded_classes.match(method.get_class_name()) :
                    l.append(method)
            return l
        else :
            return method_list

    def filter_list_of_classes(self, class_list) :
        if self.__enable_exclude_classes and class_list :
            l = []
            for i in class_list :
                if not self.__regexp_excluded_classes.match(i) :
                    l.append(i)
            return l
        else :
            return class_list

    def filter_list_of_paths(self, vm, paths):
        if self.__enable_exclude_classes and paths :
            cm = vm.get_class_manager()

            l = []
            for path in paths :
                src_class_name, src_method_name, src_descriptor =  path.get_src(cm)
                if not self.__regexp_excluded_classes.match(src_class_name) :
                    l.append(path)

            return l
        else :
            return paths

    def filter_dst_class_in_paths(self, vm, paths, excluded_class_list):
        cm = vm.get_class_manager()

        l = []
        for path in paths :
            dst_class_name, _, _ =  path.get_dst(cm)
            if dst_class_name not in excluded_class_list :
                l.append(path)

        return l

    def filter_list_of_variables(self, vm, paths) :
        """
            Example paths input: [[('R', 8), 5050], [('R', 24), 5046]]
        """

        if self.__enable_exclude_classes and paths :
            l = []
            for path in paths :
                access, idx = path[0]
                m_idx = path[1]
                method = vm.get_cm_method(m_idx)
                class_name = method[0]

                if not self.__regexp_excluded_classes.match(class_name) :
                    l.append(path)
            return l
        else :
            return paths

    def get_class_container_dict_by_new_instance_classname_in_paths(self, vm, analysis, paths, result_idx):   #dic: key=>class_name, value=>paths
        dic_classname_to_paths = {}
        paths = self.filter_list_of_paths(vm, paths)
        for i in analysis.trace_Register_value_by_Param_in_source_Paths(vm, paths):
            if (i.getResult()[result_idx] is None) or (not i.is_class_container(result_idx)) :  #If parameter 0 is a class_container type (ex: Lclass/name;)
                continue
            class_container = i.getResult()[result_idx]
            class_name = class_container.get_class_name()
            if class_name not in dic_classname_to_paths:
                dic_classname_to_paths[class_name] = []
            dic_classname_to_paths[class_name].append(i.getPath())
        return dic_classname_to_paths


class ExpectedException(Exception) :
    def __init__(self, err_id, message):
        self.err_id = err_id
        self.message = message
    def __str__(self):
        return "[" + self.err_id + "] " + self.message

    def get_err_id(self) :
        return self.err_id

    def get_err_message(self) :
        return self.message


class StringHandler :
    def __init__(self, initial_str="") :
        self.str = initial_str

    def __repr__(self) :
        return self.str

    def __str__(self) :
        return self.str

    def append(self, new_string) :
        self.str += new_string

    def appendNewLine(self) :
        self.str += "\n"

    def get(self) :
        return self.str


def toNdkFileFormat(name):
    return "lib" + name + ".so"

def get_protectionLevel_string_by_protection_value_number(num) :
    if num == PROTECTION_NORMAL :
        return "normal"
    elif num == PROTECTION_DANGEROUS :
        return "dangerous"
    elif num == PROTECTION_SIGNATURE :
        return "signature"
    elif num == PROTECTION_SIGNATURE_OR_SYSTEM :
        return "signatureOrSystem"
    else :
        return num

def isBase64(base64_string):
        return re.match('^[A-Za-z0-9+/]+[=]{0,2}$', base64_string)

def isSuccessBase64DecodedString(base64_string):
    # Punct: \:;/-.,?=<>+_()[]{}|"'~`*
    return re.match('^[A-Za-z0-9\\\:\;\/\-\.\,\?\=\<\>\+\_\(\)\[\]\{\}\|\"\'\~\`\*]+$', base64_string)

def isNullOrEmptyString(input_string, strip_whitespaces=False):
    if input_string is None :
        return True
    if strip_whitespaces :
        if input_string.strip() == "" :
            return True
    else :
        if input_string == "" :
            return True
    return False

def dump_NDK_library_classname_to_ndkso_mapping_ndk_location_list(list_NDK_library_classname_to_ndkso_mapping) :
    l = []
    for ndk_location , path in list_NDK_library_classname_to_ndkso_mapping:
        l.append(ndk_location)
    return l

def get_hashes_by_filename(filename):
    md5 = None
    sha1 = None
    sha256 = None
    sha512 = None
    with open(filename) as f:
        data = f.read()    
        md5 = hashlib.md5(data).hexdigest()
        sha1 = hashlib.sha1(data).hexdigest()
        sha256 = hashlib.sha256(data).hexdigest()
        sha512 = hashlib.sha512(data).hexdigest()
    return md5, sha1, sha256, sha512

def is_class_implements_interface(cls, search_interfaces, compare_type):
    class_interfaces = cls.get_interfaces()
    if class_interfaces is None:
        return False
    if compare_type == TYPE_COMPARE_ALL: # All
        for i in search_interfaces:
            if i not in class_interfaces:
                return False
        return True
    elif compare_type == TYPE_COMPARE_ANY: #Any
        for i in search_interfaces:
            if i in class_interfaces:
                return True
        return False

def get_method_ins_by_superclass_and_method(vm, super_classes, method_name, method_descriptor) :
    for cls in vm.get_classes() :
        if cls.get_superclassname() in super_classes :
            for method in cls.get_methods():
                if (method.get_name() == method_name) and (method.get_descriptor() == method_descriptor) :
                    yield method

def get_method_ins_by_implement_interface_and_method(vm, implement_interface, compare_type, method_name, method_descriptor) :
    """
        Example result:
            (Ljavax/net/ssl/HostnameVerifier; Ljava/io/Serializable;)
    """

    for cls in vm.get_classes() :
        if is_class_implements_interface(cls, implement_interface, compare_type) :
            for method in cls.get_methods():
                if (method.get_name() == method_name) and (method.get_descriptor() == method_descriptor) :
                    yield method

def get_method_ins_by_implement_interface_and_method_desc_dict(vm, implement_interface, compare_type, method_name_and_descriptor_list) :
    
    dict_result = {}

    for cls in vm.get_classes() :
        if is_class_implements_interface(cls, implement_interface, compare_type) :
            class_name = cls.get_name()
            if class_name not in dict_result :
                dict_result[class_name] = []

            for method in cls.get_methods():
                name_and_desc = method.get_name() + method.get_descriptor()
                if name_and_desc in method_name_and_descriptor_list :
                    dict_result[class_name].append(method)

    return dict_result

def is_kind_string_in_ins_method(method, kind_string) :
    for ins in method.get_instructions():
        try :
            if ins.get_kind_string() == kind_string:
                return True
        except AttributeError :  # Because the instruction may not have "get_kind_string()" method
            return False
    return False

def get_all_components_by_permission(xml, permission):
    """
        Return: 
            (1) activity
            (2) activity-alias
            (3) service
            (4) receiver
            (5) provider
        who use the specific permission
    """

    find_tags = ["activity", "activity-alias", "service", "receiver", "provider"]
    dict_perms = {}

    for tag in find_tags:
        for item in xml.getElementsByTagName(tag) :
            if (item.getAttribute("android:permission") == permission) or (item.getAttribute("android:readPermission") == permission) or (item.getAttribute("android:writePermission") == permission) :
                if tag not in dict_perms :
                    dict_perms[tag] = []
                dict_perms[tag].append(item.getAttribute("android:name"))
    return dict_perms


def parseArgument():
    parser = argparse.ArgumentParser(description='AndroBugs Framework - Android App Security Vulnerability Scanner')
    parser.add_argument("-f", "--apk_file", help="APK File to analyze", type=str, required=True)
    parser.add_argument("-m", "--analyze_mode", help="Specify \"single\"(default) or \"massive\"", type=str, required=False, default=ANALYZE_MODE_SINGLE)
    parser.add_argument("-b", "--analyze_engine_build", help="Analysis build number.", type=int, required=False, default=ANALYZE_ENGINE_BUILD_DEFAULT)
    parser.add_argument("-t", "--analyze_tag", help="Analysis tag to uniquely distinguish this time of analysis.", type=str, required=False, default=None)
    parser.add_argument("-e", "--extra", help="1)Do not check(default)  2)Check  security class names, method names and native methods", type=int, required=False, default=1)
    parser.add_argument("-c", "--line_max_output_characters", help="Setup the maximum characters of analysis output in a line", type=int, required=False)
    parser.add_argument("-s", "--store_analysis_result_in_db", help="Specify this argument if you want to store the analysis result in MongoDB. Please add this argument if you have MongoDB connection.", action="store_true")
    parser.add_argument("-v", "--show_vector_id", help="Specify this argument if you want to see the Vector ID for each vector.", action="store_true")

    #When you want to use "report_output_dir", remember to use "os.path.join(args.report_output_dir, [filename])"
    parser.add_argument("-o", "--report_output_dir", help="Analysis Report Output Directory", type=str, required=False, default=DIRECTORY_REPORT_OUTPUT)
    
    args = parser.parse_args()
    return args

def __analyze(writer, args) :

    """
        Exception:
            apk_file_not_exist
            classes_dex_not_in_apk
    """

    #StopWatch: Counting execution time...
    stopwatch_start = datetime.now()

    efficientStringSearchEngine = EfficientStringSearchEngine()
    filteringEngine = FilteringEngine(ENABLE_EXCLUDE_CLASSES, STR_REGEXP_TYPE_EXCLUDE_CLASSES)

    isUsingSQLCipher = False
    isMasterKeyVulnerability = False

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
        except ImportError:
            found_pymongo_lib = False

        if not found_pymongo_lib :
            pass

            # Cause some unexpected behavior on Linux => Temporarily comment it out
            # raise ExpectedException("libs_not_found_pymongo", "Python library \"pymongo\" is not found. Please install the library first: http://api.mongodb.org/python/current/installation.html.")

    #apk_filepath_relative = apk_Path
    apk_filepath_absolute = os.path.abspath(apk_Path)

    #writer.writeInf_ForceNoPrint("apk_filepath_relative", apk_filepath_relative)
    writer.writeInf_ForceNoPrint("apk_filepath_absolute", apk_filepath_absolute)

    apk_file_size = float(os.path.getsize(apk_filepath_absolute)) / (1024 * 1024)
    writer.writeInf_ForceNoPrint("apk_file_size", apk_file_size)

    writer.update_analyze_status("loading_apk")

    writer.writeInf_ForceNoPrint("time_starting_analyze", datetime.utcnow())

    a = apk.APK(apk_Path) 

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

    d = dvm.DalvikVMFormat(a.get_dex())

    writer.update_analyze_status("starting_analyze")

    vmx = analysis.VMAnalysis(d)

    writer.update_analyze_status("starting_androbugs")

    analyze_start = datetime.now()

    # ////////////////////////////////////////////////////////////////////////////////////////////////////////////


    list_detected_FLAG_DEBUGGABLE_path = []
    field_ApplicationInfo_flags_debuggable = vmx.get_tainted_field("Landroid/content/pm/ApplicationInfo;" ,"flags", "I")
    



    '''
    if field_ApplicationInfo_flags_debuggable :
        for path, stack in field_ApplicationInfo_flags_debuggable.get_paths_and_stacks(d, filteringEngine.get_filtering_regexp()):
            last_one_ins = stack.gets()[-1]
            last_two_ins = stack.gets()[-2]

            if (last_one_ins is not None) and (last_two_ins is not None) :
                try:
                    if (last_one_ins[0] == 0xDD) and (last_two_ins[1][0][1] == last_one_ins[1][1][1]) and (last_one_ins[1][2][1] == 2) :  #and-int/lit8 vx,vy,lit8
                        list_detected_FLAG_DEBUGGABLE_path.append(path)
                    """
                        Example 1:
                            last_two_ins => [82, [(0, 1), (0, 1), (258, 16, 'Landroid/content/pm/ApplicationInfo;->flags I')]]
                            last_one_ins => [221, [(0, 1), (0, 1), (1, 2)]]

                        Example 2:
                            last_two_ins => [82, [(0, 2), (0, 0), (258, 896, 'Landroid/content/pm/ApplicationInfo;->flags I')]]
                            last_one_ins => [221, [(0, 2), (0, 2), (1, 2)]]

                        Java code:
                            stack.show()
                            print(last_one_ins)
                            print(last_two_ins)
                    """
                except:
                    pass

    if list_detected_FLAG_DEBUGGABLE_path :
        writer.startWriter("HACKER_DEBUGGABLE_CHECK", LEVEL_NOTICE, "Codes for Checking Android Debug Mode", "Found codes for checking \"ApplicationInfo.FLAG_DEBUGGABLE\" in AndroidManifest.xml:", ["Debug", "Hacker"])

        for path in list_detected_FLAG_DEBUGGABLE_path:
            writer.show_single_PathVariable(d, path)
    else:
        writer.startWriter("HACKER_DEBUGGABLE_CHECK", LEVEL_INFO, "Codes for Checking Android Debug Mode", "Did not detect codes for checking \"ApplicationInfo.FLAG_DEBUGGABLE\" in AndroidManifest.xml.", ["Debug", "Hacker"])
    '''




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


def get_hash_scanning(writer) :
    # signature = hash(package_name(default="") + "-" + file_sha256(default="") + "-" + timestamp_long + "-" + random_number_length8)
    # use "-" because aaa-bbb.com is not a valid domain name
    tmp_original = writer.getInf("package_name", "pkg") + "-" + writer.getInf("file_sha256", "sha256") + "-" + str(time.time()) + "-" + str(random.randrange(10000000, 99999999))
    tmp_hash = hashlib.sha512(tmp_original).hexdigest()
    return tmp_hash

def get_hash_exception(writer) :
    # signature = hash(analyze_error_id(default="") + "-" + file_sha256(default="") + "-" + timestamp_long + "-" + random_number_length8)
    tmp_original = writer.getInf("analyze_error_id", "err") + "-" + writer.getInf("file_sha256", "sha256") + "-" + str(time.time()) + "-" + str(random.randrange(10000000, 99999999))
    tmp_hash = hashlib.sha512(tmp_original).hexdigest()
    return tmp_hash

def __persist_file(writer, args) :

    package_name =  writer.getInf("package_name")
    signature_unique_analyze =  writer.getInf("signature_unique_analyze")

    if package_name and signature_unique_analyze :
        return writer.save_result_to_file(os.path.join(args.report_output_dir, package_name + "_" + signature_unique_analyze + ".txt"), args)
    else :
        print("\"package_name\" or \"signature_unique_analyze\" not exist.")
        return False


def main() :

    args = parseArgument()

    writer = Writer()

    try :

        #Print Title
        writer.writePlainInf("""*************************************************************************
**   AndroBugs Framework - Android App Security Vulnerability Scanner  **
**                            version: 1.0.0                           **
**     author: Yu-Cheng Lin (@AndroBugs, http://www.AndroBugs.com)     **
**               contact: androbugs.framework@gmail.com                **
*************************************************************************""")

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


if __name__ == "__main__":
    main()


"""
    Packages do not check:
        java
        android
        com.google
        org.apache
        org.json
        org.xml
"""
