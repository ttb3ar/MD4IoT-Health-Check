# MD4IoT-Health-Check  
An application to remotley check the uptime of Microsoft Defender for IoT network sensors using ping and ssh commands.   
  
**Features:**  
-encrypt credentials using AES  
-reads encrypted file and preforms health check   
-edit encrypted file in decryption editor  
--pings sensor ip  
--ssh's into admin account and runs "system sanity"  
--su into cyberx account and runs "uptime"  
-supports multiple sensors  
-supports multiple languages  
--open source language supprt: just create a .json folder in the format of the existing ones  
-configure test parameters  
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
### EN:  
<img width="1920" height="1008" alt="bd47776e-d582-45f6-b9d4-f6080e1ac3b6" src="https://github.com/user-attachments/assets/f988bfc1-74cd-4596-901b-5e2a8b5af04c" />
<img width="1920" height="1008" alt="15eecd93-dea3-47a7-ba19-17db52a5f0e0" src="https://github.com/user-attachments/assets/5a608abd-0f7f-4e74-a608-ee222709d1b8" />
<img width="1920" height="1008" alt="b0a10d62-f9ea-4fe8-a6a1-d8022452cbb2" src="https://github.com/user-attachments/assets/fff1439e-b173-4636-b5a9-c11374fe4887" />
<img width="752" height="948" alt="c3013bb0-efc1-4556-9af8-004b0808d938" src="https://github.com/user-attachments/assets/2346ed8f-c1a4-423d-88d6-ba02924e05d5" />
  
  
### JP:  
<img width="1920" height="1008" alt="a00cb46e-808a-4feb-9e23-735130628562" src="https://github.com/user-attachments/assets/5dd86e05-7f7c-44bd-9b4e-395951d248f8" />
<img width="1920" height="1008" alt="9c5b9b1e-432d-4d2d-8275-8b2365296d39" src="https://github.com/user-attachments/assets/14c96345-526a-4e6f-a4b5-9b2898dbcc4a" />
<img width="1920" height="1008" alt="26c66f6b-6c52-4c49-be58-eff35ef659cb" src="https://github.com/user-attachments/assets/9e31a127-0042-4573-89b3-0c472da9ac96" />
<img width="1920" height="1008" alt="385f510e-33c1-4759-ac6a-3d8aa72f7ef1" src="https://github.com/user-attachments/assets/fa54955c-522b-4867-8469-5705b6629370" />
<img width="752" height="948" alt="7dea476f-427b-44ad-a003-03033081ead9" src="https://github.com/user-attachments/assets/da04af3a-aca2-4d64-8fba-6a3824a4cf74" />
