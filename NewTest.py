import NewParser
if __name__ == "__main__":
    f=open('Tests/Test_Cases/SimpleSmaliTest/MainActivity.smali','r')
    smali_class=NewParser.parseSmaliFiles(f)
    print(smali_class.classname)
    for f in smali_class.fields:
        print(f.name,f.value)