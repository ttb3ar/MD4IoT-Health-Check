# MD4IoT-Health-Check  
An application to remotley check the uptime of Microsoft Defender for IoT sensors via ping and running ssh commands.   
  
Credentials should be stored in a .json format such as in the example file in this repo  
The best practice would then be to encrypt it and store the resulting key in a safe place  
(probably best to delete the original .json too)    
  
Would just upload the .exe but github has a 25mb upload limit:  
to turn the .py into an exe you'll want to run:  
  pip install pyinstaller  

make sure you have the translation folder, favicon, and .py all in one folder. cd to that folder  
then do:  

  pyinstaller --add-data "translations;translations" --onefile --noconsole --icon=favicon.ico --name="MD4IoT SSH Ping Check" voltron4.py

To do:
make it faster on boot
rework language logic so anyone can add their own languages
