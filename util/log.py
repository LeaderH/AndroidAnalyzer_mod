# -*- coding=utf8 -*-
import logging

DEBUG=logging.DEBUG
WARNING=logging.WARNING
ERROR=logging.ERROR
INFO=logging.INFO

class Logger:
    def __init__(self, path,clevel = DEBUG,Flevel = DEBUG):
        self.logger = logging.getLogger(path)
        self.logger.setLevel(DEBUG)
        fmt = logging.Formatter('[%(asctime)s] [%(levelname)s] %(message)s', '%Y-%m-%d %H:%M:%S')
       
        sh = logging.StreamHandler()
        sh.setFormatter(fmt)
        sh.setLevel(clevel)
       
        fh = logging.FileHandler(path)
        fh.setFormatter(fmt)
        fh.setLevel(Flevel)
        self.logger.addHandler(sh)
        self.logger.addHandler(fh)
 
    def debug(self,message):
        self.logger.debug(message)
 
    def info(self,message):
        self.logger.info(message)
 
    def war(self,message):
        self.logger.warn(message)
 
    def error(self,message):
        self.logger.error(message)
 
    def cri(self,message):
        self.logger.critical(message)
 
 
 
if __name__ =='__main__':
    logTest = Logger('test.log',WARNING,DEBUG)
    logTest.debug('debug中文')
    logTest.info('info')
    logTest.war('warning')
    logTest.error('error')
    logTest.cri('critical中文')