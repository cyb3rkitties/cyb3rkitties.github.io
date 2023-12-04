---
title: ExeWho2 - A Tool from the Wild 
author: al3x
date: 2023-12-04 12:47:00 -0600
categories: [research]
tags: [threat hunting, red teaming, malicious tool]
---

ExeWho2 appears to be a red teaming command line tool that can be used to deliver and execute obfuscated payloads on compromised systems. It's written in Rust and it appears to be an [evolution of Exe\_who.](https://github.com/whokilleddb/exe_who "Exe_who Github Repository")

The tool and its source code were found in the wild while performing **threat hunting and analysis on open directories** via the [Censys database](https://search.censys.io/ "Censys.io Search"), along with a parser script written in Python that can be used to prepare the payload for execution via ExeWho2. Moreover, a UPX-packed sample containing string references to ExeWho2 was found on VirusTotal (big thanks to Maxime Thiebaut for this info).

# ExeWho2 Modules and Functionality

[ExeWho2](https://github.com/cyb3rkitties/exewho2 "ExeWho2") is comprised of a main module, along with four other files: CLI, detectors, fetch, and patcher, which give a good idea of the functionalities of the tool.

## Payload Preparation

Before using the tool, a payload has to be prepared, which can be done using the Python script [parser.py](https://github.com/cyb3rkitties/exewho2/parser.py "Parser"):

![parser-py-cli-header.png](exewho2/parser-py-cli-header.png)

The script optionally xors the payload with a key determined by user input, then appends a PNG header to the encrypted binary for further obfuscation.

![parser-py-encrypt.png](exewho2/parser-py-encrypt.png)

After that, the payload can be uploaded onto one or more servers. A json file containing the URL(s) has to be created and subsequently fed to ExeWho2 via the command line.

![servers-json.png](exewho2/servers-json.png)

## Usage and Features (main.rs and fetch.rs)

ExeWho2 takes one mandatory argument: the URL of the json file containing the list of servers where the binary is located.

![cli-usage.png](exewho2/cli-usage.png)

The tool also offers a --help menu that explains usage and arguments.

![cli-help.png](exewho2/cli-help.png)

Once launched with a valid URL, the tool will fetch the json file, parse it, and fetch the payload(s) from the server(s).

![json-payload-download.png](exewho2/json-payload-download.png)
*To reveal download capabilities, I simulated the network connection by using a separate VM and python http server.*

The README file found with the source code also describes the error exit codes that the tool has the ability to throw.

![exit-codesd.png](exewho2/exit-codes.png)

### Decryption of the Payload

If the payload was encrypted during preparation using parser.py, ExeWho2 offers the --key option to decrypt the binary after download and before execution.

![cli-with-key.png](exewho2/cli-with-key.png)

### Execution of the Payload

To execute the decrypted payload, ExeWho2 uses [Memexec](https://crates.io/crates/memexec), a tool for loading and executing binaries from memory.

![payload-execution.png](exewho2/payload-execution.png)

### Detection of Sandbox Environment (detectors.rs)

Whenever the sandbox detection option is selected (--ds), the tool checks for the presence of files indicating that execution is happening in a virtual environment.

![sandbox-detection.png](exewho2/sandbox-detection.png)

### Disabling ETW and AMSI (patchers.rs)

[ETW](https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/event-tracing-for-windows--etw-) is the event tracing functionality on Windows systems that, in normal conditions, records events raised by user-mode applications and kernel-mode drivers. ExeWho2 has the capability to disable event tracing and does so by loading ntdll.dll via LoadLibrary, finding EtwEventWrite via GetProcAddress, changing memory permissions of the EtwEventWrite region with VirtualProtect, and subsequently overwriting one byte.

![etw-patch.png](exewho2/etw-patch.png)

[AMSI](https://learn.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal) is the Windows Antimalware Scan Interface, which normally provides anti-malware protection by acting as an interface between applications and anti-malware products. ExeWho2 disables AMSI by using a similar API call sequence as the one used to disable ETW: it starts by loading amsi.dll, then gets the address of AmsiScanBuffer, changes memory protection of the related region, and overwrites six bytes of the function.

![amsi-patch.png](exewho2/amsi-patch.png)

The full source code, which I found along with a number of payloads, is available in this [Github repository](https://github.com/cyb3rkitties/exewho2).

## Hunting ExeWho2: Sigma rule

To facilitate hunting and detection for this new tool, I wrote a Sigma rule which is also available in the related Github Repository.

```sigma
title: ExeWho2 Use
id: ea36c9f1-6aca-4668-8e50-5e4955ec42f3
status: experimental
description: Detects the usage of ExeWho2 CLI tool
references:
    - https://cyb3rkitties.github.io/exewho2-download-execution-payload-red-teaming
    - https://github.com/cyb3rkitties/exewho2
author: al3x perotti (cyb3rkitties)
date: 2023/12/04
tags:
    - attack.execution
    - attack.defense_evasion
    - attack.command_and_control
    - attack.t1059
    - attack.t1071
    - attack.t1105
    - attack.t1027
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Image|endswith:
            - '\exewho2.exe'
        - CommandLine|contains:
            - ' -u http://*.json '
            - ' -u *.json* '
    condition: selection
level: high
```

???? REFLECTIVE CODE LOADING
