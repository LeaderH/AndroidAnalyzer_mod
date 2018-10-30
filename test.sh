#!/bin/bash
if [ "$1" != "" ]; then
	python ./AndroBugs_Framework/androbugs.py -f /home/leader/Desktop/androguard_imp/SampleApplication/2048.apk
else
	python3 analysis.py -f /home/leader/Desktop/androguard_imp/SampleApplication/2048.apk
fi	
