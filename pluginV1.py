#This script integrates the In Nomine Function project for the prediction and substitution of function names
#@author tronux7
#@category In Nomine Function
#@keybinding
#@menupath
#@toolbar

from ghidra.util.task import TaskMonitorComponent
from ghidra.app.util.exporter import BinaryExporter
from ghidra.util.exception import UsrException
from java.io import File
from java.awt import Color
import java.lang.IllegalArgumentException
import java.io.IOException
import os
import time
import subprocess
import ConfigParser

#GLOBALS
program_path = "" #path to the current program
config_folder = "" #path to the .config folder

asv = [] #address set view list
asv_instruction_iterators = [] #iterators for each asv

function_names = [] #names of non empty, non thunk functions
function_addresses = [] #string representation of the adresses of non empty, non thunk functions
function_address_obj = [] #list of Address objects
predicted_names = [] #function names after the prediction

instructions = [] #instructions in each function
inst_addr_inst_list = [] #debug
addr_symbol = [] #will be written in symbols.csv. (targetAddress, functionName)
calls = [] #debug

files = [] #file objects of the exported bins

exporter = BinaryExporter() #exporter object
tm = TaskMonitorComponent() #task monitor for export
listing = currentProgram.getListing() #listing of the current program
fm = currentProgram.getFunctionManager() #function manager
functions = fm.getFunctions(True) #all the functions of the current program


#ANALYZE CHANGES IN THE CURRENT PROGRAM (IF ANY)
def analyze_changes():
	try:
		analyzeChanges(currentProgram)
        
	except IllegalArgumentException as e:
		print("[EXCEPTION]: " + str(e))
	return


#ASKS FOR THE In Nomine Function PATH
def const_path():
	try:
		inf_path = str(askDirectory("Select the INF directory", "Choose").getAbsolutePath())

	except UsrException as e:
		print("[EXCEPTION]: " + str(e))
	return inf_path


#CONFIG
def config():
	config_folder = os.path.join(os.path.expanduser("~"), ".config", "plugin")
	
	if not os.path.exists(config_folder):
		os.makedirs(config_folder)

	config_file = "plugin.conf"
	config_file_path = os.path.join(config_folder, config_file)

	if not os.path.exists(config_file_path) or os.stat(config_file_path).st_size == 0:
		parser = ConfigParser.ConfigParser()
        
		inf_path = const_path()

		parser.add_section("PATH")
		parser.set("PATH", "inf", inf_path)

		with open(config_file_path, "w") as conf:
			parser.write(conf)

	return config_folder


#ASKS THE .pred FILE AND TRAINED MODEL PATH
def ask_paths():
	try:
    
		program_path = str(currentProgram.getExecutablePath())

		pred_path = str(askDirectory("Select a destination for the pred file", "Choose").getAbsolutePath())

		model_path = str(askFile("Select the trained model you want to use", "Choose").getAbsolutePath())
        
	except (UsrException, UnboundLocalError) as e:
		print("[EXCEPTION]: " + str(e))


	return [pred_path, model_path]


#CREATES FUNCTIONS, ASVs, FNAME LISTS. CREATES TEMP BIN FILES
def setup():
	monitor.checkCanceled()

	for f in functions:
		if listing.getInstructionAt(f.getEntryPoint()) != None and f.isThunk() == False :
			asv.append(f.getBody())
			func = f.getEntryPoint()
			function_names.append(str(f.getName()))
			function_address_obj.append(func)
			function_addresses.append(str(func))

	for a in asv:
		asv_instruction_iterators.append(listing.getInstructions(a, True))
	

	temp_folder = os.path.join(os.path.expanduser("~"), ".config", "plugin", "temp")
	if not os.path.exists(temp_folder):
		os.makedirs(temp_folder)
	
	temp_file = "temp.csv"
	temp_file_path = os.path.join(temp_folder, temp_file)
	with open(temp_file_path, "w") as f:
		for i in range(len(function_addresses)):
			if i == len(function_addresses)-1:
				s = "0x"+str(function_addresses[i])+","+str(function_names[i])
				f.write(s)

			else:
				s = "0x"+str(function_addresses[i])+","+str(function_names[i])+"\n"
				f.write(s)


	for name in function_names:
		s = temp_folder+"/"+name+".bin"
		f = File(s)
		files.append(f)
	
	time.sleep(1)
	monitor.incrementProgress(1)

	return

#RETRIEVES ALL THE INSTRUCTIONS IN ALL THE FUNCTIONS
def retrieve_instructions():
	monitor.checkCanceled()

	for aii in asv_instruction_iterators:
		while aii.hasNext() == True:
			inst = aii.next()
			instructions.append(inst)
	
	time.sleep(1)
	monitor.incrementProgress(1)

	return

#CREATES A symbol.csv FILE IN .config/temp/ FOLDER CONSISTING IN THE SYMBOLIC NAME AND THE ADDRESS OF ALL CALLS
def get_symbols():
	monitor.checkCanceled()

	for instruction in instructions:
		inst = ""
		inst_addr = instruction.getAddress().toString()

		if instruction.getMnemonicString() == "CALL":
			called = instruction.getPrimaryReference(0)
			target_addr = called.getToAddress()
			
			func = getFunctionContaining(target_addr)

			if func != None:
				calls.append(called)
				function_name = func.getName()
				inst = 'CALL {}'.format(function_name)
				addr_symbol.append((str(target_addr), str(function_name)))

		else:
			inst = instruction.toString()

		inst_addr_inst_list.append((inst_addr, inst)) #for debug
	
	symbols_folder = os.path.join(os.path.expanduser("~"), ".config", "plugin", "temp")
	symbols_file = "symbols.csv"
	symbols_file_path = os.path.join(symbols_folder, symbols_file)
	with open(symbols_file_path, "w") as f:
		for i in range(len(addr_symbol)):
			if i == len(addr_symbol)-1:
				s = addr_symbol[i][0]+","+addr_symbol[i][1]
				f.write(s)
			else:
				s = addr_symbol[i][0]+","+addr_symbol[i][1]+"\n"
				f.write(s)

	time.sleep(1)
	monitor.incrementProgress(1)

	return


#DELETES TEMP FILES AND FOLDERS	
def clear():
	#TODO delete temp files (maybe)
	return


#EXPORTS ALL THE FUNCTIONS AS  BINARIES
def export():
	monitor.checkCanceled()

	try:
		for i in range(len(asv)):
			exporter.export(files[i], currentProgram, asv[i], tm.checkCanceled())
	except IOException as e:
		print("[EXCEPTION]: " + str(e))

	time.sleep(1)
	monitor.incrementProgress(1)

	return


#FILTER ASM INSTRUCTIONS (CALLS EXTERNAL filter.py SCRIPT)
def call_filter():
	monitor.checkCanceled()

	try:
		filter_path = os.path.join(os.path.expanduser("~"), "plugin_ghidra", "filter.py")

		print("[RUNNING]: python3"+" "+filter_path)
		p = subprocess.Popen("python3"+" "+filter_path, shell=True, stdout=subprocess.PIPE)
	
	except (OSError, ValueError, NameError) as e:
		print("[EXCEPTION]: " + str(e))

	time.sleep(1)
	monitor.incrementProgress(1)

	return


#PREDICT SCRIPT (CALLS INF)
def predict(args):
	monitor.checkCanceled()

	try:
		parser = ConfigParser.SafeConfigParser()
		parser.read(str(os.path.join(os.path.expanduser("~"), ".config", "plugin", "plugin.conf")))
		inf_path = parser.get("PATH", "inf")

		filtered_file = os.path.join(os.path.expanduser("~"), ".config", "plugin", "temp", "filtered.asm")
		print("[RUNNING]: sh"+" "+inf_path+"/predict.sh"+" "+filtered_file+" "+args[0]+"/predicted.pred"+" "+args[1])
		p = subprocess.Popen("sh"+" "+inf_path+"/predict.sh"+" "+filtered_file+" "+args[0]+"/predicted.pred"+" "+args[1], shell=True, stdout=subprocess.PIPE)	
	
		monitor.incrementProgress(1)
	
		for line in p.stdout.readlines():
			print(line)
	
	except (OSError, ValueError, NameError) as e:
		print("[EXCEPTION]: " + str(e))

	time.sleep(1)
	monitor.incrementProgress(1)
	time.sleep(1)
	popup("Done prediction!")
	
	return

#SETS FUNCTION NAMES IN THE LISTING AS PLATE COMMENT (NEW, OLD)
def update_names():
	monitor.checkCanceled()
	with open(args[0]+"/predicted.pred") as f:
		lines = f.readlines()
		for line in lines:
			predicted_names.append(line.strip())
	
	for i in range(len(function_address_obj)-1):
		setBackgroundColor(function_address_obj[i], Color.CYAN)
		codeUnit = listing.getCodeUnitAt(function_address_obj[i])
		codeUnit.setComment(codeUnit.PLATE_COMMENT, "FUNCTION\n"+"OLD: "+function_names[i]+"\n"+"NEW: "+predicted_names[i])
	
	old_new_path = str(os.path.join(os.path.expanduser("~"), ".config", "plugin", "temp"))
	with open(old_new_path + "/old_new.csv", "w") as f:
		for i in range(len(function_names)):
			f.write(function_names[i]+","+predicted_names[i]+"\n")
	monitor.incrementProgress(1)	

	time.sleep(1)
	monitor.incrementProgress(1)
	popup("Predicted names have been added as a plate comment.")
	return

def call_sender():
	monitor.checkCanceled()
	hostname = ""
	port = ""
	sender_path = os.path.join(os.path.expanduser("~"), "plugin_ghidra", "sender.py")
	answ = askYesNo("1.000.000$ question", "Do you want to send function binaries and names to another computer?")
	
	if answ == True:
		hostname = askString("Hostname", "Insert target hostname")
		port = askString("Port", "Insert port number (> 6000)")
		print("[RUNNING]: python3 "+sender_path+" "+hostname+" "+port)
		p = subprocess.Popen("python3"+" "+sender_path+" "+hostname+" "+port, shell=True, stdout=subprocess.PIPE)

		time.sleep(1)
		monitor.incrementProgress(1)
		popup("Binaries and names have been sent to "+hostname)
		
	return

#MAIN:
analyze_changes()
config_folder = config()
args = ask_paths()
monitor.initialize(10)

setup()
export()
retrieve_instructions()
get_symbols()
call_filter()
predict(args)
update_names()
call_sender()
