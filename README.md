# DVWA-SQL-Cli
Short python CLi that will detect an sql injection vulnerability



###### **Requirements
  - Download a copy of dvwa VM: http://www.dvwa.co.uk/DVWA-1.0.7.iso
 	- Python3
 	- virtualenv

###### **Setup

   Set the python3 enviroment up

 ```
   $ cd ~/DVWA-SQL-Cli/
   $ virtualenv env
   $ . env/bin/activate
   $ pip install -r requirements.txt
 ```

  
###### **Usage
  To see menu:
    - python main.py 
      
  To Run Application:
  ```
  python main.py start <URL of DVWA>
  ```
