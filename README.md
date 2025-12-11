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
add launcher for better packaging  
enhance logging (seperate per day/month, etc.)  
automatic mode to intergrate with task scheduler  

## Screenshots:
<img width="1920" height="1008" alt="ee855205-596c-4e3a-8ced-9b5a37fbebd3" src="https://github.com/user-attachments/assets/b89a44be-0fb1-4499-89c5-b128ba61f788" />
<img width="1920" height="1008" alt="74ec6c74-9a88-4543-a263-6fb6a880bffa" src="https://github.com/user-attachments/assets/22321547-1f61-43dc-b9f3-a1a2e0ba3a5c" />
<img width="1920" height="1008" alt="4adc5117-9805-45c3-a78b-761944530ffc" src="https://github.com/user-attachments/assets/b92d5a18-7037-47ca-a5c3-4caf84168725" />
