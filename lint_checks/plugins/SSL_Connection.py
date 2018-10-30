from util.analysisUtil import *
from util.analysisConst import *
#from tools.modified.androguard.core.bytecodes import apk
#from tools.modified.androguard.core.bytecodes import dvm
#from tools.modified.androguard.core.analysis import analysis
#from tools.modified.androguard.core import bytecode
import util.log

name = "SSL_URLS_NOT_IN_HTTPS"
description = "SSL Connection Checking"
tags=["SSL_Security"]

def getName():
    #"return analysis name"
    return name

def getDescription():
    #"return analysis description"
    return description

def getTags():
    return tags

def run(a,d,vmx,writer):
	all_permissions = a.get_permissions()

	allstrings = d.get_strings()
	allurls_strip_duplicated = []
	efficientStringSearchEngine = EfficientStringSearchEngine()
	filteringEngine = FilteringEngine(ENABLE_EXCLUDE_CLASSES, STR_REGEXP_TYPE_EXCLUDE_CLASSES)

	exception_url_string = ["http://example.com",
							"http://example.com/",
							"http://www.example.com",
							"http://www.example.com/",
							"http://www.google-analytics.com/collect",
							"http://www.google-analytics.com",
							"http://hostname/?",
							"http://hostname/"]

	for line in allstrings:
		if re.match('http\:\/\/(.+)', line):    #^https?\:\/\/(.+)$
			allurls_strip_duplicated.append(line)

	allurls_strip_non_duplicated = sorted(set(allurls_strip_duplicated))
	allurls_strip_non_duplicated_final = []

	if allurls_strip_non_duplicated:
		for url in allurls_strip_non_duplicated :
			if (url not in exception_url_string) and (not url.startswith("http://schemas.android.com/")) and \
													 (not url.startswith("http://www.w3.org/")) and \
													 (not url.startswith("http://apache.org/")) and \
													 (not url.startswith("http://xml.org/")) and \
													 (not url.startswith("http://localhost/")) and \
													 (not url.startswith("http://java.sun.com/")) and \
													 (not url.endswith("/namespace")) and \
													 (not url.endswith("-dtd")) and \
													 (not url.endswith(".dtd")) and \
													 (not url.endswith("-handler")) and \
													 (not url.endswith("-instance")) :
				# >>>>STRING_SEARCH<<<<
				efficientStringSearchEngine.addSearchItem(url, url, False)	#use url as "key"

				allurls_strip_non_duplicated_final.append(url)
	# ------------------------------------------------------------------------

	#Base64 String decoding:
	list_base64_success_decoded_string_to_original_mapping = {}
	list_base64_excluded_original_string = ["endsWith", "allCells", "fillList", "endNanos", "cityList", "cloudid=", "Liouciou"] #exclusion list

	for line in allstrings :
		if (isBase64(line)) and (len(line) >= 3) :
			try:
				decoded_string = base64.b64decode(line)
				if isSuccessBase64DecodedString(decoded_string) :
					if len(decoded_string) > 3:
						if (decoded_string not in list_base64_success_decoded_string_to_original_mapping) and (line not in list_base64_excluded_original_string):
							list_base64_success_decoded_string_to_original_mapping[decoded_string] = line
							# >>>>STRING_SEARCH<<<<
							efficientStringSearchEngine.addSearchItem(line, line, False)
			except:
				pass

	# ------------------------------------------------------------------------

	# >>>>STRING_SEARCH<<<<

	#start the search core engine
	efficientStringSearchEngine.search(d, allstrings)			
	# ------------------------------------------------------------------------

	#pre-run to avoid all the urls are in exclusion list but the results are shown
	allurls_strip_non_duplicated_final_prerun_count = 0
	for url in allurls_strip_non_duplicated_final :
		dict_class_to_method_mapping = efficientStringSearchEngine.get_search_result_dict_key_classname_value_methodlist_by_match_id(url)
		if filteringEngine.is_all_of_key_class_in_dict_not_in_exclusion(dict_class_to_method_mapping) :
			allurls_strip_non_duplicated_final_prerun_count = allurls_strip_non_duplicated_final_prerun_count + 1


	if allurls_strip_non_duplicated_final_prerun_count != 0:
		writer.startWriter(name, LEVEL_CRITICAL, description, \
			"URLs that are NOT under SSL (Total:" + str(allurls_strip_non_duplicated_final_prerun_count) + "):", \
			 tags)
		
		for url in allurls_strip_non_duplicated_final :

			dict_class_to_method_mapping = efficientStringSearchEngine.get_search_result_dict_key_classname_value_methodlist_by_match_id(url)
			if not filteringEngine.is_all_of_key_class_in_dict_not_in_exclusion(dict_class_to_method_mapping) :
				continue

			writer.write(url)

			try :
				if dict_class_to_method_mapping :  #Found the corresponding url in the code
					for _ , result_method_list in dict_class_to_method_mapping.items() :
						for result_method in result_method_list :  #strip duplicated item
							if filteringEngine.is_class_name_not_in_exclusion(result_method.get_class_name()) :
								source_classes_and_functions = (result_method.get_class_name() + "->" + result_method.get_name() + result_method.get_descriptor())
								writer.write("    => " + source_classes_and_functions)
					
			except KeyError:
				pass
	else:
		writer.startWriter(name, LEVEL_INFO, description, \
			"Did not discover urls that are not under SSL \
			(Notice: if you encrypt the url string, we can not discover that).", \
			tags)	
