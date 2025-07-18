# MD4IoT-Health-Check  
An application to remotley check the uptime of Microsoft Defender for IoT network sensors using ping and ssh commands.   
  
Capabilities:  
-encrypt credentials using AES  
-reads encrypted file and preforms health check 
--pings sensor ip  
--ssh's into admin account and runs "system sanity"  
--ssh's into cyberx account and runs "uptime"  
-supports multiple sensors  
-supports multiple languages  
--open source language supprt: just create a .json folder in the format of the existing ones  
-log and export results in .csv format  
  
Credentials should be stored in a .json format such as in the example file  
Then encrypt using the program before storing the outputted key in a secure location  
Best to delete the original .json  
  
## Setup
Place the application, icon, .enc/.json files, and transaltions folder (contaning files) in the same directory  
  
## To run  
cd to the directory you have the application saved and:
python MSP.py

*Alternativley:*  
Would just upload the .exe but github has a 25mb upload limit:  
run:  
  pip install pyinstaller  
  
make sure you have the translation folder, favicon, and .py all in one folder. cd to that folder  
then do:  
  
  pyinstaller --add-data "translations;translations" --onefile --noconsole --icon=favicon.ico --name="MD4IoT SSH Ping Check" msp3.py  


## To do:
optimize boot speed  
add launcher for better packaging  
enhance logging  
