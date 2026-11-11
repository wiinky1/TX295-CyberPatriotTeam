Do the forensic questions first then run the cyberpatriot_user_manger.sh script

how to run the scripts 

step: 1 make the script excutable

in the folder that you downloaded the scripts run these command

chmod +x cyberpatriot_user_manager.sh

chmod +x Run_after_forensic.sh

step: 2 define users

make a .txt file named admins.txt, and add the Admin users to it

make a .txt file named allowed.txt, and add the Authorized users to it

EXAMPLE: FILES

admins.txt

benjamin
jpearson
hspecter
llitt


allowed.txt

pporter
kbennett
zlawford
kdurant
skeller
hgunderson
jkirkwood
rzane
dpaulsen

step: 3 run the script

run the command: sudo ./cyberpatriot_user_manager.sh admins.txt allowed.txt --apply

this will run the script, if you would like to do a dry-run the delete the "--apply"

step: 4 run the lock down script

run command: sudo ./Run_after_forensic.sh