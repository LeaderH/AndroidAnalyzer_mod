import imp
import os
import json
import sys
import util.log

logger = util.log.Logger('Analysis.log',util.log.WARNING,util.log.DEBUG)

try:
    plugins_conf = json.loads(open('plugins.json').read())
    config = json.loads(open('config.json').read())
except Exception as e:
    logger.error("Couldn't load config files")
    sys.exit(1)

AnalysisFolders = config['plugin_path']

def getPlugins():
    plugins = []
    possibleplugins = {} # name => folder, name collisions will be overwritten.
    for folder in AnalysisFolders:
        for plugin in os.listdir(folder):
            plugin_name=os.path.splitext(plugin)[0]
            if not plugin_name.startswith("__"): #ignore hidden files
                try:
                    info = imp.find_module(plugin_name, [folder])
                    do_append = False
                    if plugin_name not in plugins_conf.keys() or 'enabled' not in plugins_conf[plugin_name].keys():
                        do_append = True
                    #add unknown plugin to json as default
                    elif plugin_name in plugins_conf.keys() and 'enabled' in plugins_conf[plugin_name].keys() \
                       and plugins_conf[plugin_name]['enabled'] == True:
                        do_append = True

                    if do_append:
                        plugins.append({"name": plugin_name, "info": info})
                        
                    else:
                        logger.info("{0} : Disabled".format(plugin_name))
                except ImportError as err:
                    logger.debug('ImportError:'+ str(err))
    return plugins

def loadPlugin(plugin):
    return imp.load_module(plugin["name"], *plugin["info"])

def runPlugins(a,d,vmx,writer):
    #results = {}

    for i in getPlugins():
        logger.info("Loading Module " + i["name"])
        plugin = loadPlugin(i)
        logger.info(i["name"] + " : Running")
        try:
            plugin.run(a,d,vmx,writer)
        except Exception as e:
            print("Failed to run {}: {}" .format(i["name"],str(e)))
            #results = plugin.getResults(results)
    pass
    #return results