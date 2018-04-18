#python3

import sys
import traceback

#class to represent codes
class code_t:
	def __init__(self):
		self.instruction=""
		self.modify_register=""
		self.register_v=[]
		self.value=""
#class to represent location of codes
class location_t:
	def __init__(self):
		self.classname=""
		self.start=0
		self.end=0
		self.code=[]
		self.methodType=[]
		self.codes=[]
#class to represent a class field
class field_t:
	def __init__(self):
		self.name=""
		self.type=""
		self.keywords=""
		self.value=""
		self.fieldInfo=[]
		self.line=0

class metric_t:
	def __init__(self):
		self.DSC=0.0
		self.NOH=0.0
		self.ANA=0.0
		self.DAM=0.0
		self.MOA=0.0
		self.DCC=0.0
		self.CAM=0.0
		self.MFA=0.0
		self.NPM=0.0
		self.CIS=0.0

class class_t:
	def __init__(self):
		self.path=""
		self.classname=""
		self.keywords=""
		self.super=""
		self.source=""	
		self.subclass=""
		self.fields=[]	
		self.methods=[]	
		self.interfaces=[]
		self.metrics=[]


def main(argv):
    code =code_t()
    #parse_register("invoke-virtual {p0,v1,v3}, Lcom/testApp/MainActivity;->testFunction()V",code)
    field=field_t()
    parse_field(".field private static final IS_FULLSCREEN_PREF:Ljava/lang/String; = \"is_fullscreen_pref\"",4,field)
    print(field.name,field.type,field.value)
    pass

def parse_register(line,code):
	line=line.split('{')[1].split('}')[0]
	code.register_v+=line.split(',')
	#print(code.register_v)


def parse_field(line,lineno,field):
    field.line=lineno
    field.value=line.split('=')[1] if len(line.split('='))>1 else ""
    field.keywords = line.split('=')[0].split(' ')[1:-1]
    field.name = line.split('=')[0].rstrip().split(' ')[-1].split(':')[0]
    field.type = line.split('=')[0].rstrip().split(' ')[-1].split(':')[1][:-1]



def parseSmaliFiles(content):
    """
    Parse smali code into python directory
    """
    smali_class = class_t()
    smaliClassName = content.readline()
    smali_class.classname= smaliClassName.split(' ')[-1][:-1]
    smali_class.keywords = smaliClassName.split(' ')[1:-1]
    #smali_class['Metrics'] = {'Reflections':0,'Methods':0,'Invocations':0}
    #smali_class['Methods'] = []
    #smali_class['Fields'] = []
    #smali_class['Loader'] = []
    ##smali_class['Dependecies'] = []
    ##smali_class['Annotations'] = []
    line = content.readline()
    lineno=0
    try:
        while line:
            lineno+=1
            if line.startswith('.super'):
                smali_class.super = line.split(' ')[1][:-1]
            elif line.startswith('.annotated'):
                # TODO: Handle Annotations
                # this may take more research into different types of annotations
                pass
            elif line.startswith('.source'):
                smali_class.source = line.split(' ')[1][1:-2]
            elif line.startswith('.implements'):
                smali_class.interfaces += line.split(' ')[1][:-1]
            elif line.startswith('.field'):
                field = field_t()
                parse_field(line,lineno,field)
                smali_class.fields.append(field)
            elif line.startswith('.method'):
            	pass
            else:
                pass
            line = content.readline()


    except:
        print(line)
        tb = traceback.format_exc()
        print(tb)
        sys.exit(1)
    return smali_class


if __name__ == "__main__":
	main(sys.argv)
