import smaliparser
import analyzer
import Analysis

if __name__ == "__main__":
    f=open('Tests/Test_Cases/SimpleSmaliTest/MainActivity.smali','r')
    # for i in Analysis.getPlugins():
        # #print("Loading routine " + i["name"])
        # plugin = Analysis.loadPlugin(i)
        # #print(i["name"] + " : Running")
        # print(plugin.getName())
        # print("\t"+plugin.getDescription())
        # #plugin.run(dependencies,classes,sharedobjs)
        # #results = plugin.getResults(results)
        
    smali_class=smaliparser.parseSmaliFiles(f)
    class_dict={'MainActivity':smali_class}
    re=analyzer.analyzeParsedSmali(class_dict,1)
    print re

    # for m in smali_class['Methods']:
        # for k,v in m.iteritems():
            # if k!="Code":
                # print k,v
        # print ">"*15
    
    # for key,v in smali_class.iteritems():
            # print key ,v
    # internalDep=[]
    # for m in smali_class['Methods']:
        # for deps in m['Dependencies']:
            # #dep after invoke-xxx
            # methodDeps = deps.lstrip(" [L.").rstrip(";").split('$')[0].split('/')
            # print methodDeps
            # cleanDeps = []
            # for level in methodDeps:
                # cleanDeps.append(level)
            # if cleanDeps.__len__() > 4:
                # internalDep.append(cleanDeps[0] + "/" + cleanDeps[1] + "/" + cleanDeps[2] + "/" + cleanDeps[3])
            # elif cleanDeps.__len__() > 3:
                # internalDep.append(cleanDeps[0] + "/" + cleanDeps[1] + "/" + cleanDeps[2])
            # elif cleanDeps.__len__() > 2:
                # internalDep.append(cleanDeps[0] + "/" + cleanDeps[1])
            # else:
                # internalDep.append(cleanDeps[0])
                
    # print internalDep       
            # for level in methodDeps:
                # print level
        # for k,v in m.iteritems():
            # print k,v
        # print ">"*15
            
            
    #print smali_class
    #re=analyzer.getDependencies(class_dict)
    # for r in re:
        # if type(r) is set:
            # print list(r)
        # else:
            # print r
    #analyzer.findMethodsWithDependencies(smali_class)
