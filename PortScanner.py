"""
Author: Christopher Booker
7/7/2026
christopher.booker5@studytafensw.edu.au
Copyright: Red Opal Innovations
License: Proprietary
Last Update:
Version v1.0.1
Status: development
Dependencies:
- Administrative priviledges for running on windows
- Sudo priviledges for running on MacOS and Linux
- Python 3.x
- PyWin32 on Windows
- Event Log on Windows
Description:
A port scanner that logs output to the console, private logging file and system logs on windows/linux.
IP ranges are specified in the CLI, and ports are specified by a user made list of files.
Users are also able to skip odds/evens and set an excluded IP address range.
Arguments in silent mode use the following format:
<IP address> <subnet mask> <port type> <step> <port list> <excluded IP range>
default values are:
192.168.0.0 255.255.255.0 tcp odd ports.txt .\\ 10
"""

import datetime
import socket
import platform
import ctypes
import sys
import os
import ipaddress
import subprocess

portType = "TCP"
targetPrefix = "192.168.0.0/24"
targetMask = "255.255.255.0"
cidrMask = "/24"
portList = "ports.txt"
IPstep = "Odd Only"
excludedIP = 10
logFile = ".\\"
operatingSystem = ""


##This function check the operating system the user is running the scan on
##This will determine later whether log will be set to syslog or windows event
##This will also determine what arguments are passed to the terminal when pining hosts
def OSCheck():
    global operatingSystem
    checkOS = platform.system()
    if checkOS == "Windows":
        return checkOS
    if checkOS == "Linux":
        return checkOS
    if checkOS == "Darwin":
        return checkOS
    _ = input(f"""Unrecognised OS detected: {checkOS}\n 
        Closing Program, Press 'Enter' to continue: """)
    sys.exit()

##OS check needs to run before sudo privileges can be checked
operatingSystem = OSCheck()

##As the port scanner needs sudo/admin privileges to run
##This function will check the priviledges of the user and exit for regular users
def sudoCheck() -> None:
    global operatingSystem
    if operatingSystem == "Windows":
        if not ctypes.windll.shell32.IsUserAnAdmin():
            _ = input("""Program wasn't launched with administrator priviledges and will terminate.
                \nPlease run the program again as administrator.
                \nTerminating program now, press 'Enter' to continue: """)
            sys.exit()

    if operatingSystem == "Linux" or operatingSystem == "MacOS":
        if not os.getuid() == 0:
            _ = input("""Program wasn't launched with administrator priviledges and will terminate.
                \nPlease run the program again as administrator.
                \nTerminating program now, press 'Enter' to continue: """)
            sys.exit()

##Before the rest of the program is started we call the sudo check function 
##The program will terminate if the user has no admin/sudo privileges.
sudoCheck()

##This creates an entry into the event log
##allowing entries to be recognised by windows and logged properly
def winCheck():
    win32evtlogutil.AddSourceToRegistry(
        appName="PortScanner",
        msgDLL=r"%SystemRoot%\System32\EventCreate.exe",
        eventLogType="Application",
    )

##This if statement imports the required modules for logging events on windows
##if the OS is windows
if operatingSystem == "Windows":
    import win32evtlogutil
    import win32evtlog
    import win32event

##This calls the winCheck function only if the user is running on windows.
if operatingSystem == "Windows":
    winCheck()

##This creates a function for logging to event log
##Only if the user is on windows.
if operatingSystem == "Windows":

    def winEventLog(source, eventID, message):
        try:
            win32evtlogutil.ReportEvent(
                appName=source,
                eventID=eventID,
                eventCategory=1,
                eventType=win32evtlog.EVENTLOG_INFORMATION_TYPE,
                strings=[message],
                data=b"",
            )
        except Exception as e:
            if len(sys.argv) == 1:
                print(
                    f"The following error occured when trying to write log to windows event\n{e}\ncontinuing with scan."
                )
            logPrivate(
                fileLog,
                f"The following error occured when trying to write log to windows event\n{e}\ncontinuing with scan.",
            )

##This function checks that any user inputed IP addresses are valid.
##It will return True if the checks are passed and False otherwise
def prefixCheck(address):
    if len(address.split(".")) == 4:
        if (
            -1 < int(address.split(".")[0]) < 256
            and -1 < int(address.split(".")[1]) < 256
            and -1 < int(address.split(".")[2]) < 256
            and -1 < int(address.split(".")[3]) < 256
        ):
            return True

##This function checks that any user inputed subnet masks are valid.
##It will return True if the checks are passed and False otherwise
def maskCheck(mask):
    if len(mask.split(".")) == 4:
        if int(mask.split(".")[0]) == 255:
            if int(mask.split(".")[1]) == 255:
                if int(mask.split(".")[2]) == 255:
                    if int(mask.split(".")[3]) in [
                        0,
                        128,
                        192,
                        224,
                        240,
                        248,
                        252,
                        254,
                        255,
                    ]:
                        return True

        if int(mask.split(".")[0]) == 255:
            if int(mask.split(".")[1]) == 255:
                if int(mask.split(".")[2]) in [
                    0,
                    128,
                    192,
                    224,
                    240,
                    248,
                    252,
                    254,
                    255,
                ]:
                    if int(mask.split(".")[3]) == 0:
                        return True

        if int(mask.split(".")[0]) == 255:
            if int(mask.split(".")[1]) in [
                0,
                128,
                192,
                224,
                240,
                248,
                252,
                254,
                255,
            ]:
                if int(mask.split(".")[2]) == 0:
                    if int(mask.split(".")[3]) == 0:
                        return True

        if int(mask.split(".")[0]) in [
            0,
            128,
            192,
            224,
            240,
            248,
            252,
            254,
            255,
        ]:
            if int(mask.split(".")[1]) == 0:
                if int(mask.split(".")[2]) == 0:
                    if int(mask.split(".")[3]) == 0:
                        return True

##This function returns the binary value of a subnet mask
##This is used later to generate a cidr mask
def maskToBinary(mask):
    octets = mask.split(".")
    binOctets = [bin(int(octet))[2:].zfill(8) for octet in octets]
    binMask = "".join(binOctets)
    return binMask

##If a user inputs a port list that doesn't exist this function is called
##Users then populate the list with ports the want to scan.
def createPortList(userPortList):
    try:
        f = open(userPortList, "x")
        f.close()
        portList = userPortList
        print("Please populate your new ports list.")
        ports = []
        while True:
            try:
                port = input(
                    'Please enter a port number or "break" to end.\nInput: '
                ).strip()
                if port.lower() == "break":
                    break
                if port.isdigit():
                    if int(port) in range(0, 65535):
                        ports.append(port)
                    else:
                        print("Invalid input. Please enter a valid port number.")
                else:
                    print("Invalid input. Please enter a valid port number.")
            except ValueError:
                print("Invalid input. Please enter a valid port number.")
        for port in ports:
            try:
                with open(portList, "a") as f:
                    f.write(f"{port}\n")
            except FileNotFoundError as e:
                print(
                    f"The following error occured while writing ports to file\n{e}\nFile may not be accessible."
                )
            except Exception as e:
                print(
                    f"The following error occured while writing to file\n{e}\nUnknown error."
                )
    except Exception as e:
        if len(sys.argv) > 1:
            sys.exit(f"Unable to create file, the following error was generated:\n{e}")
        print(f"Unable to create file, the following error was generated:\n{e}")
        return

##This function formats the users passed path to log files
##It then sets the path as the path to save logfiles to.
def createLogFile(userLogFile):
    global logFile
    try:
        if operatingSystem == "Windows":
            userLogFile.strip("\\")
            logFile = userLogFile + "\\"
        else:
            userLogFile.strip("/")
            logFile = userLogFile + "/"
        os.mkdir(logFile)
    except Exception as e:
        print(f"Unable to create directory, the following error was generated:\n{e}")
        if len(sys.argv) > 1:
            sys.exit("Exiting program")
        return

##This function checks all the arguments the user passesare valid.
##if arguments are passed the program will commence in silent mode
##The program will exit if arguments are invalid.
def argsCheck():
    global targetPrefix
    global targetMask
    global cidrMask
    global portType
    global IPstep
    global portList
    global logFile
    global excludedIP
    if len(sys.argv) == 2:
        if prefixCheck(sys.argv[1]):
            targetMask = "255.255.255.255"
            cidrMask = "/32"
            targetPrefix = ipaddress.ip_network(f"{sys.argv[1]}{cidrMask}")
        else:
            sys.exit("Invalid IP address detected. Format must be 1.2.3.4")

    if len(sys.argv) >= 3:
        if prefixCheck(sys.argv[1]):
            if maskCheck(sys.argv[2]):
                targetMask = sys.argv[2]
                maskBinary = maskToBinary(targetMask)
                cidrMask = f"/{str(maskBinary.count('1'))}"
                targetPrefix = ipaddress.ip_network(f"{sys.argv[1]}{cidrMask}")
            else:
                sys.exit("Invalid subnet mask detected. Format must be 0.0.0.0")
        else:
            sys.exit("Invalid IP address detected. Format must be 1.2.3.4")

    if len(sys.argv) >= 4:
        if str(sys.argv[3]).lower() in ["tcp", "udp"]:
            portType = sys.argv[3].upper()
        else:
            sys.exit(
                f'Invalid port type detected. must be "TCP" or "UDP".\nGot {sys.argv[3]}.'
            )

    if len(sys.argv) >= 5:
        if sys.argv[4].lower() == "all":
            IPstep = "Scan All"
        elif sys.argv[4].lower() == "odd":
            IPstep = "Odd Only"
        elif sys.argv[4].lower() == "even":
            IPstep = "Even Only"
        else:
            sys.exit('Invalid step option. Must be "all", "odd", or "even".')

    if len(sys.argv) >= 6:
        if os.path.exists(sys.argv[5]):
            portList = sys.argv[5]
        else:
            userInput = input(
                "Port List file doesn't exist, would you like to create one(y/N)?"
            ).strip()
            if userInput.lower() == "y":
                createPortList(sys.argv[5])
            else:
                sys.exit("File not created. Exiting program.")

    if len(sys.argv) >= 7:
        if os.path.isdir(sys.argv[6]):
            logFile = sys.argv[6]
        else:
            userInput = input(
                "Path doesn't exist, would you like to create one(y/N)?"
            ).strip()
            if userInput.lower() == "y":
                createLogFile(sys.argv[6])11
            else:
                print("File not created. Logging may not perform as expected.")

    if len(sys.argv) >= 8:
        if sys.argv[7].isdigit():
            if -1 < int(sys.argv[7]) < 256:
                excludedIP = int(sys.argv[7])
            else:
                sys.exit("Invalid input detected. Excluded IP must be integer 0-255.")
        else:
            sys.exit("Invalid input detected. Excluded IP must be integer 0-255.")

##This function specifies the layout of the main menu
##The menu is displayed in interactive mode and the user can then input options to work the program.
def mainMenu():
    global portType
    while True:
        _ = input("Press 'Enter' to continue...")
        print(f"""
                Port Type = {portType}
                Target Prefix = {targetPrefix} 
                Path to Port List = {portList}
                Path to Log File = {logFile}
                Adresses in Network to be Scanned = {IPstep}
                """)
        print("What would you like to do?")
        print("""
            1) Set IP Prefix\n
            2) Set TCP Scan\n
            3) Set UDP Scan\n
            4) Set Address Skipping\n
            5) Set Path to Port List\n
            6) Set Path to Private Log\n
            7) Set how many of the first host addresses in the network to be skipped.\n
            Scan) Scan Network\n
            Exit) Terminate the program
            """)
        userDecision = str(input("Input: "))
        if userDecision == "1":
            setPrefix()
        if userDecision == "2":
            portType = "TCP"
        if userDecision == "3":
            portType = "UDP"
        if userDecision == "4":
            setStep()
        if userDecision == "5":
            setPortList()
        if userDecision == "6":
            setPrivateLog()
        if userDecision == "7":
            setExcluded()
        if userDecision.lower() == "scan":
            if portType == "TCP":
                TCPscanNetwork()
            if portType == "UDP":
                UDPscanNetwork()
        if userDecision.lower() == "exit":
            sys.exit("Program terminated")

##When called by the user this function prompts the user for a target prefix
##and sets the prefix if the users input passes a check
def setPrefix():
    global targetMask
    global targetPrefix
    global cidrMask
    try:
        netAddAndMask = input(
            "Please enter a valid network address followed by a subnet mask(example. 192.168.0.0 255.255.255.0)\nInput: "
        ).strip()
        if len(netAddAndMask.split(" ")) == 2:
            address, mask = netAddAndMask.split(" ")
            if prefixCheck(address):
                if maskCheck(mask):
                    targetMask = mask
                    maskBinary = maskToBinary(targetMask)
                    cidrMask = f"/{str(maskBinary.count('1'))}"
                    targetPrefix = ipaddress.ip_network(f"{address}{cidrMask}")
                    return

        print("Invalid input detected, please try again.")
    except ValueError:
        print("Invalid input detected, please try again.")

##This allows users to specifiy whether odd/even/all ip address are scanned
##This is set to odd by default.
def setStep():
    global IPstep
    while True:
        stepMode = input(
            "Set the skipping mode (All/Even/Odd/Explain)\nInput: "
        ).strip()
        if stepMode.lower() == "all":
            IPstep = "Scan All"
            break
        if stepMode.lower() == "even":
            IPstep = "Even Only"
            break
        if stepMode.lower() == "odd":
            IPstep = "Odd Only"
            break
        if stepMode.lower() == "explain":
            print("""
            All) All IP addresses in the specified network will be scanned.
            Even) Only addresses ending in an even number will be scanned.
            Odd) Only addresses ending in an odd number will be scanned.
            """)
        print("Invalid input detected, please try again.")

##This funcation prompts the user and sets the file to read ports from
##If the file doesn't exist the user will be offered to create it.
def setPortList():
    global portList
    userPort = input("""Please enter the path to the list of ports you wish to scan
                            \nPaths on windows require double backslash \\\\ between directories
                            \ninput: """).strip()
    if os.path.exists(userPort):
        portList = userPort
    else:
        userInput = input(
            "Port List file doesn't exist, would you like to create one(y/N)?"
        ).strip()
        if userInput.lower() == "y":
            createPortList(userPort)
        else:
            print("File not created.")

##When called by the user it will prompt the user to enter 
##the path to the location they would like private logs to be saved to.
def setPrivateLog():
    global logFile
    userFile = input("""Please enter the path to the directory you wish to save logs to.
                            \nPaths on windows require double backslash '\\\\' between directories.
                            \ninput: """).strip()
    if os.path.exists(userFile):
        logFile = userFile
    else:
        userInput = input(
            "Directory doesn't exist, would you like to create one(y/N)?"
        ).strip()
        if userInput.lower() == "y":
            createLogFile(userFile)
        else:
            print("File not created.")

##When called by the user, this will prompt the user for the number of IP addresses
##That they want to skip from the target IP ranges (default 10)
def setExcluded():
    global excludedIP
    try:
        userInput = input("""Please enter how many IP addresses you wish to excluded from the scan.
                                \ninput: """).strip()
        if userInput.isdigit():
            if -1 < int(userInput) < 256:
                excludedIP = int(userInput)
    except ValueError:
        print("Invalid input detected. Input must be integer 0-255")

##During the port scan, a ICMP ping will be sent to all hosts
##before scanning the ports, This funciton contains that logic.
def pingHost(hostIP):
    global operatingSystem
    if operatingSystem == "Windows":
        try:
            output = subprocess.check_output(
                ["ping", "-n", "3", "-w", str(2000), str(hostIP)],
                stderr=subprocess.STDOUT,
            ).decode()
            unreachable = [
                "Destination host unreachable",
                "Request timed out",
                "could not find host",
            ]
            if any(msg in output for msg in unreachable):
                return False
            return True
        except Exception:
            return False
    else:
        try:
            subprocess.check_output(["ping", "-c", "3", "-W", str(2), str(hostIP)])
            return True
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            return False

##This function attempts to connect to ports, for a certain range of ports
##that tend to retrun false positives a banner grab is also performed.
def scanPort(hostIP, portNum, timeout=2):
    try:
        socketConnect = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socketConnect.settimeout(timeout)
        isOpen = socketConnect.connect_ex((str(hostIP), portNum))
        if isOpen != 0:
            return False
        if portNum in [21, 22, 23, 25, 110, 143, 389, 2289, 5060, 5900]:
            if len(sys.argv) == 1:
                print(f"Port {portNum} may return false positive.")
            if operatingSystem == "Windows":
                winEventLog(
                    "PortScanner", 4, f"Port {portNum} may return false positive."
                )
            else:
                logSyslog(f"Port {portNum} may return false positive.")
            try:
                banner = socketConnect.recv(1024)
                if len(banner) > 0:
                    print(f'Port {portNum} returned banner "{banner}"')
                    return len(banner) > 0
            except:
                return False
        return True
    except socket.error:
        return False

##This function calculates which targets from the given IP range
##will be actually scanned based on the parameters given by the user.
def calcTargets():
    targets = []
    try:
        for hostIP in ipaddress.ip_network(f"{targetPrefix}"):
            targets.append(hostIP)
    except Exception as e:
        print(
            f"""The following error was generated\n{e}\nThere may be an issue or bug related to the set target prefix."""
        )
        return []

    try:
        targets = targets[excludedIP:]
    except Exception as e:
        print(
            f"""The following error was generated\n{e}\nUser set excluded address may be greater than range of subnet to be scanned."""
        )
        return []

    finalTargets = []
    for target in targets:
        if IPstep == "Odd Only":
            if int(str(target).split(".")[3]) % 2 == 1:
                finalTargets.append(target)
        if IPstep == "Even Only":
            if int(str(target).split(".")[3]) % 2 == 0:
                finalTargets.append(target)
        if IPstep == "Scan All":
            finalTargets = targets[:]
    return finalTargets

##This funtion writes the private logs and includes error handling.
def logPrivate(passedLog, message):
    try:
        with open(passedLog, "a") as log:
            log.write(message)
    except FileNotFoundError as e:
        if len(sys.argv) == 1:
            print(
                f"The following message was generated when trying to write to private log\n{e}\nFile may not exist."
            )
        with open(passedLog, "r") as f:
            lastLine = f.readlines()[-2]
        if "The following message was generated when trying to write to" in lastLine:
            return
        if operatingSystem == "Windows":
            winEventLog(
                "PortScanner",
                3,
                f"The following message was generated when trying to write to private log\n{e}\nFile may not exist.",
            )
        else:
            logSyslog(
                f"The following message was generated when trying to write to private log\n{e}\nFile may not exist."
            )
    except Exception as e:
        if len(sys.argv) == 1:
            print(
                f"The following message was generated when trying to write to private log\n{e}"
            )
        with open(passedLog, "r") as f:
            lastLine = f.readlines()[-2]
        if "The following message was generated when trying to write to" in lastLine:
            return
        if operatingSystem == "Windows":
            winEventLog(
                "PortScanner",
                3,
                f"The following error occured when trying to write log to private log\n{e}\ncontinuing with scan.",
            )
        else:
            logSyslog(
                f"The following message was generated when trying to write to private log\n{e}"
            )

##This function writes messages to syslog and is only called on UNIX machines.
def logSyslog(message):
    import syslog

    try:
        syslog.openlog(
            ident="PortScanner",
            logoption=syslog.LOG_PID,
            facility=syslog.LOG_LOCAL0,
        )
        syslog.syslog(syslog.LOG_INFO, message)
        syslog.closelog()
    except Exception as e:
        if len(sys.argv) == 1:
            print(
                f"The following message was generated when trying to write to syslog\n{e}"
            )
        logPrivate(
            fileLog,
            f"The following message was generated when trying to write to syslog\n{e}",
        )

##This function iterates through all the hosts that will be scanned and call
##ping, port scan, and logging functions based on the users parameters
##and environment.
def TCPscanNetwork():
    global logFile
    tdnow = str(datetime.datetime.now())[:19]
    tdnow = tdnow.replace(":", "-").replace(" ", "_")
    f = open(f"{logFile}{tdnow[:19]}_ip_tcp_port_log.txt", "x")
    f.close()
    global fileLog
    fileLog = f"{logFile}{tdnow[:19]}_ip_tcp_port_log.txt"

    scanHeader = f"""
            Scan will commence at {datetime.datetime.now()} with the following settings:\n
            portType = {portType}\n
            targetPrefix = {targetPrefix}\n
            portList = {portList}\n
            IPstep = {IPstep}\n
            excludedIP = {excludedIP}\n
            logFile = {logFile}\n"""
    if len(sys.argv) == 1:
        print(scanHeader)
        print(" ###Scanning now. Please wait...###")
    logPrivate(fileLog, scanHeader)
    if operatingSystem == "Windows":
        winEventLog("PortScanner", 4, scanHeader)
    else:
        logSyslog(scanHeader)

    finalTargets = calcTargets()
    for hostIP in finalTargets:
        ICMPResponse = pingHost(hostIP)
        logMessage = (
            f"{datetime.datetime.now()} -- {hostIP} - ICMP response received. Host is up\n"
            if ICMPResponse
            else f"{datetime.datetime.now()} -- {hostIP} - No ICMP response. Host is down or not responding to/blocking ICMP requests.\n"
        )
        if len(sys.argv) == 1:
            print(logMessage)
        logPrivate(fileLog, logMessage)

        if ICMPResponse:
            if operatingSystem == "Windows":
                winEventLog("PortScanner", 4, logMessage)
            else:
                logSyslog(logMessage)
        else:
            if operatingSystem == "Windows":
                winEventLog("PortScaner", 3, logMessage)
            else:
                logSyslog(logMessage)

        try:
            with open(portList, "r") as list:
                ports = [int(line.strip()) for line in list if line.strip().isdigit()]
        except FileNotFoundError as e:
            if len(sys.argv) == 1:
                logPrivate(
                    fileLog,
                    f"The following error occured when trying to open port list file.\n{e}\nThe file may not exist.",
                )
                if operatingSystem == "Windows":
                    winEventLog(
                        "PortScanner",
                        3,
                        f"The following error occured when trying to open port list file.\n{e}\nThe file may not exist.",
                    )
                else:
                    logSyslog(
                        f"The following error occured when trying to open port list file.\n{e}\nThe file may not exist."
                    )
                print(
                    f"The following error occured when trying to open port list file.\n{e}\nThe file may not exist."
                )
            if len(sys.argv) > 1:
                logPrivate(
                    fileLog,
                    f"The following error occured when trying to open port list file.\n{e}\nThe file may not exist.",
                )
                if operatingSystem == "Windows":
                    winEventLog(
                        "PortScanner",
                        3,
                        f"The following error occured when trying to open port list file.\n{e}\nThe file may not exist.",
                    )
                else:
                    logSyslog(
                        f"The following error occured when trying to open port list file.\n{e}\nThe file may not exist."
                    )
                sys.exit("Exiting program.")
            return

        except Exception as e:
            if len(sys.argv) == 1:
                logPrivate(
                    fileLog,
                    f"The following error occured when trying to open port list file.\n{e}\nUnknown error.",
                )
                if operatingSystem == "Windows":
                    winEventLog(
                        "PortScanner",
                        3,
                        f"The following error occured when trying to open port list file.\n{e}\nUnknown error.",
                    )
                else:
                    logSyslog(
                        f"The following error occured when tryng to open port list file.\n{e}\nUnknown error."
                    )
                print(
                    f"The following error occured when trying to open port list file.\n{e}\nUnknown error."
                )
            if len(sys.argv) > 1:
                logPrivate(
                    fileLog,
                    f"The following error occured when trying to open port list file.\n{e}\nUnknown error.",
                )
                if operatingSystem == "Windows":
                    winEventLog(
                        "PortScanner",
                        3,
                        f"The following error occured when trying to open port list file.\n{e}\nUnknown error.",
                    )
                else:
                    logSyslog(
                        f"The following error occured when tryng to open port list file.\n{e}\nUnknown error."
                    )
                sys.exit("Exiting program.")
            return

        for port in ports:
            portOpen = scanPort(hostIP, port, 2)
            portMessage = (
                f"{datetime.datetime.now()} -- Port {port} on host {hostIP} is open.\n"
                if portOpen
                else f"{datetime.datetime.now()} -- Port {port} on host {hostIP} is closed.\n"
            )
            if len(sys.argv) == 1:
                print(portMessage)

            logPrivate(fileLog, portMessage)

            if portOpen:
                if operatingSystem == "Windows":
                    winEventLog("PortScanner", 4, portMessage)
                else:
                    logSyslog(portMessage)
            else:
                if operatingSystem == "Windows":
                    winEventLog("PortScanner", 3, portMessage)
                else:
                    logSyslog(portMessage)
    if operatingSystem == "Windows":
        winEventLog("PortScanner", 3, f"Scan completed at {datetime.datetime.now()}")
    else:
        logSyslog(f"Scan completed at {datetime.datetime.now()}")
    logPrivate(fileLog, f"Scan completed as {datetime.datetime.now()}")
    if len(sys.argv) == 1:
        print(f"Scan completed at {datetime.datetime.now()}")

##This is a function reserved for scanning UDP ports
##Stil in development
def UDPscanNetwork():
    print("Still in development, please check IT department for details")

##This functions will commence scanning if arguments are passed by the user.
##Silent mode.
if len(sys.argv) > 1:
    argsCheck()
    if portType == "UDP":
        UDPscanNetwork()
    if portType == "TCP":
        TCPscanNetwork()

##This funciton will call the main menu if the user passes no arguments.
##Interactive mode.
if len(sys.argv) == 1:
    mainMenu()
