# MD4IoT-Health-Check  
An application to remotley check the uptime of Microsoft Defender for IoT network sensors using ping and ssh commands.   
  
**Features:**  
-encrypt credentials using AES  
-reads encrypted file and preforms health check   
--pings sensor ip  
--ssh's into admin account and runs "system sanity"  
--su into cyberx account and runs "uptime"  
-supports multiple sensors  
-supports multiple languages  
--open source language supprt: just create a .json folder in the format of the existing ones  
-log and export results in .csv format  
  
Credentials should be stored in a .json format such as in the example file  
Then encrypt using the program before storing the outputted key in a secure location  
Best to delete the original .json  
  
## Setup
Click on download to get the installer  
  
Alternativley:  
Place the application, icon, .enc/.json files, and transaltions folder (contaning files) in the same directory  
  
## To run  
cd to the directory you have the application saved and:
python MSP.py

*Alternativley:*  
Would upload the .exe but github has a 25mb upload limit:  
run:  
  pip install pyinstaller  
  
make sure you have the translation folder, favicon, and .py all in one folder. cd to that folder  
then do:  
  
  pyinstaller --add-data "translations;translations" --onefile --noconsole --icon=favicon.ico --name="MD4IoT SSH Ping Check" MSP3.py  


## To do:
optimize boot speed   
enhance logging capabilities (forwarding results to syslog, customizable output, etc.)  
automatic mode to intergrate with task scheduler  

## Screenshots:
<img width="1920" height="1008" alt="691043a7-c954-476b-9f45-457148c52120" src="https://github.com/user-attachments/assets/0755b1a4-8f72-477f-802f-3836f250d974" />
<img width="1920" height="1008" alt="ebcf7ccd-aadf-4654-b29a-0f6bc1a53522" src="https://github.com/user-attachments/assets/8f25e8ec-e046-45bb-8a36-7ca85c8618ac" />
<img width="1920" height="1008" alt="4862b87a-5937-4577-b58b-302b1558d694" src="https://github.com/user-attachments/assets/2caffc3c-b65a-49d7-bf8a-5eedaa5fd510" />
