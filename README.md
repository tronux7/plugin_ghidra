# plugin_ghidra
Integration of the In Nomine Function project in Ghidra

## Requirements
* Linux system
* Ghidra SRE
* Satisfy all the requirements in https://github.com/gadiluna/in_nomine_function

## Installation
1. Clone https://github.com/gadiluna/in_nomine_function into your */home* directory and literally follow all the instructions.
Once you have successfully installed and *tested* their program, come back here and continue.

2. Clone this repo into your */home* directory

3. Copy the *plugin.py* file and paste it into the *ghidra_scripts* folder. You will find it in the *In Nomine Function* collection inside the Code Browser tool

4. (Optional) If you want to use the receiver.py trial server you have to edit the destination path in the receiver.py script itself. 

## How to use
Open a program in Ghidra then launch the plugin.py script (from Ghidra)
You will be asked where you want to save the .pred file, where is *INF* located, and which trained model you want to use.
When the execution is finished, you will see that all the functions in the program have been highligthed and the predicted names have been added as a plate comment.

## How it works
### plugin.py
The script is executed inside Ghidra.
Retrieves all the functions of the current program and exports them as binary files. These files will be given as input to the *In Nomine Function* program, generating a meaningful prediction of the function names based on what these functions do.
Generates a config file to save some user interaction time, as well as temporary files and folders.
Eventually adds the predicted names as plate comments in the code listing.

### filter.py
This script is called by the call_filter function in plugin.py and executes *externally* of Ghidra (with system python). It prepares the instructions of the functions to be given to *INF*. The script generates files that will be read back in plugin.py

### sender.py
This script is called by the call_sender function in plugin.py and executes *externally* of Ghidra (with system python). It asks the user for a IP address or host name and a port and sends the predicted names and function binaries to another computer with a TCP socket.

### receiver.py
An example of a server that receives data sent by the sender.py
