# Detect Log4J attack for QRadar SIEM
### Python script useful for detecting attack attempts by exploiting the Log4J vulnerability.
This script uses the APIs provided by IBM QRadar SIEM to query the log database.
First, the script runs an ariel query to detect all payloads that match a certain pattern.
Once these logs have been detected, an analysis is carried out to determine whether the payload is malicious or not. In the event of a malicious payload, the data of interest is extracted to continue the search with a second query.
The second query takes care of recovering all connections made to malicious destinations (contained in malicious payloads). If this query returns results, it is very likely that an attack was successful.
Finally, by performing a join between the results of the two queries, it is possible to obtain information such as the IP of the attacker, the vulnerable machine and the malicious destination.
The script also supports the sending of a log in a specific format that can be used for opening offenses directly on QRadar.

## Authors
[Salvatore Lia](https://github.com/SalvatoreLia), [Mattia Pranzini](https://github.com/MattiaPranzini)

## Introduction
The script must not be run directly on a QRadar appliance. The script is intended to run on an outside system to poll data from QRadar.
The script was tested using Pyhton 3.9.7 and may work with earlier and later versions as well. Please check that it works correctly with your version of python.
This script uses IBM QRadar APIs. For information see the link [IBM QRadar APIs samples](https://github.com/IBM/api-samples).

## Steps to configure QRadar
### Create authentication tokens
The authentication token generated by QRadar must have permissions to execute queries. It is recommended to create a token dedicated to this application.
As an alternative to the token, it is also possible to use username and password, but this operation is not recommended for security reasons.

### Install the extension (optional)
In order to have a greater customizability of the script, the possibility of using an extension for the detection of malicious payloads has been added. Specifically, within the extension it is possible to indicate a regular expression capable of detecting a specific type of attack with greater precision.
If you want to use the extension it will be sufficient to indicate the -ext parameter in the execution as specified in detail in the following paragraphs.
There is a sample extension in this repository that can be modified as desired for your case. In case of use,you can only modify the contents of the `execute` function, remembering that it must return a boolean value.

### Create New Log Source Type
In order to detect the logs used for the opening of the offenses it is necessary to create a new Log Source Type called, for example "ExternalOpenOffense".
This must contain the following properties:
| Name | Type |
|:--:|:--:|
| Type | Text |
| AttackerIP | IP Address |
| ContactedIP | IP Address |
| VulnerableIP | IP Address |
| ContactedTime | Date in format "DD/MM/yyyy HH:mm:ss" |

### Customize the DSM to detect properties
After creating the Log Source Type, specify how the properties are detected using Regex override in the DSM Editor.
| Name | Regex | Capture Group |
|:--:|:--:|:--:|
| Type | type=(.*?)\| | 1 |
| AttackerIP | source=(.*?)\| | 1 |
| ContactedIP | contacted=(.*?)\| | 1 |
| VulnerableIP | dest=(.*?)\| | 1 |
| ContactedTime | (\d{1,2}\/\d{1,2}\/\d\d\d\d \d{1,2}:\d{1,2}:\d{1,2}) | 1 |

### Definition of the Log Source
Example values:
| Field | Value |
|:--:|:--:|
| Log Source Name | Python@ExternalOffense |
| Log Source Type | ExternalOpenOffense  |
| Protocol Configuration | Syslog (Undocumented)  |
| Log Source Identifier | ExternalOffense|
| Coalescing Events | not checked |

### Definition of the rule to open the offenses
After completing the previous steps it is possible to create the rule dedicated to opening an offense when the event described above is detected.
Go to the rules creation wizard and search for "when the event (s) were detected by one or more of these log sources", select as log sources `Python@ExternalOffense`
Proceed with the configuration according to your needs.

## Instructions for using the script DetectLog4JAttack.py

### Requirements
- QRadar system 7.3 or higher
- Python 3.9 (tested)
- pandas
- [jndi_deobfuscate](https://github.com/awslabs/jndi-deobfuscate-python) (included in this repo)

All the repository's files must be contained in the same folder.  It is important to do the first run manually to set the various parameters.

### First run
Run DetectionLog4JAttack.py and enter the required data as QRadar ip address or hostname and choose the authentication method with token or username and password. After entering the data, you are asked to save. Reply with yes. If successful, the program is ready.

### Usage: DetectionLog4JAttack.py [-h] [-t "time"] [-ms millis] [-o] [-r2l] [-ext] [-v] 
options: 

  **-h, --help**   show the help message
  **-t "time"**   "last n hours|minutes|seconds"|"start 'YYYY-MM-DD hh:mm' stop 'YYYY-MM-DD 			hh:mm'" (where n is integer) Make sure you also write the quotes 
  **-ms millis**  (default=300ms) max milliseconds to evaluate the correlation between first attempt 		and connection to malicious destination 
  **-o**        shows offense on console and NOT send offense to QRadar 
  **-r2l**     (R2L) if present, the query 1 considers only Remote To Local log. 
  **-ext**     if present, the query 1 uses DETECT::LOG4J extension on payload to detect attempt 
  **-v**         print detailed operations, useful for debug 

### Running with cron
The program is written to run every 1 hour. It is recommended to run it starting a few minutes after minute 00 of every hour.
Ex: if the program is run at 18:05 it considers the logs received from 17:00 to 18:00

The script uses a text file where the last run time is saved. In the event that some previous hours have not been processed, the program will attempt to recover up to a maximum of 3 consecutive hours.

If you want to run a time other than 1 hour in cron, you must set the time (`-t`) parameter with "last" followed by the chosen time period. In this case it is possible that some attempts will not be detected if performed between two cron runs.
To avoid this problem it is possible to indicate a slightly longer time in the time parameter, in this case duplicate offenses could be generated.
 
### Certificate check
In the event that QRadar does not have a valid certificate, the execution could give an error. In this case in the RestApiClient file there is the `nocert` variable to be set to True.