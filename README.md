﻿# ETP Threat Event Query script


## How to use
1. rename etp_credential.txt.sample to etp_credential.txt. Then put your information accordingly.
2. Run the script!

## Notice  
At the first execution, the scirpt will query the past 7 days threat events from your ETP server. The request time and date will be written into a file called "former_end_time.txt".  
At the second execution, the script query threat events from the recorded time in "former_ent_time.txt" to the latest time. 
