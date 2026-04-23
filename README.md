# PsychLab

Hybrid Active Directory security lab built on my own hardware. I set up everything from scratch on Hyper-V and connected it to Microsoft Sentinel through Azure Arc for threat detection, attack simulation, and automated incident response.

The whole thing simulates a real enterprise environment. I can run actual attacks against it, detect them in Sentinel with custom KQL rules, and have incidents automatically trigger email notifications through a Logic App playbook. I built this as a portfolio project and to get hands-on experience for the SC-200 exam.

Halfway through building this I realised I was basically recreating the same architecture as the CyberRange I used during my SOC Analyst internship at Log'n Pacific. Same pipeline, same tooling, just built by me from the ground up on local hardware.


## Architecture diagram

<img width="1131" height="1083" alt="image" src="https://github.com/user-attachments/assets/f8aa71e4-d506-47f4-929a-83dc88c53c9d" />

## What I built

The domain is called psychlab.local. DC01 is the Domain Controller running Windows Server 2022 at 10.0.0.10 and WKS01 is the workstation running Windows 11 Enterprise at 10.0.0.20. Both are on an internal switch for lab traffic and an external switch for internet access.

I set up a proper AD structure with three departments (IT, HR, Finance), four user accounts across them, three security groups, and a service account with an SPN. The whole thing runs on Hyper-V on my Ryzen 9800X3D build.

### Users

| User | Username | Department | Group | Notes |
|------|----------|------------|-------|-------|
| James Carter | jcarter | IT | IT-Admins | Domain Admin (deliberate misconfiguration) |
| Emily Chen | echen | IT | IT-Admins | Standard user |
| Sarah Mitchell | smitchell | HR | HR-Staff | Pre-auth disabled (AS-REP Roasting target) |
| David Okonkwo | dokonkwo | Finance | Finance-Team | Standard user |
| svc_sqlservice | svc_sqlservice | IT | n/a | Service account with SPN (Kerberoasting target) |

## Deliberate misconfigurations

I introduced three misconfigurations on purpose to create realistic attack paths.

The service account svc_sqlservice has an SPN set (MSSQLSvc/DC01.psychlab.local:1433) which makes it a Kerberoasting target. Sarah Mitchell has Kerberos pre-authentication disabled so she can be hit with AS-REP Roasting. And jcarter was added to Domain Admins to create a privilege escalation path.

## Telemetry

Sysmon v15.20 is running on both machines using Olaf Hartong's sysmon-modular config. I went with this over SwiftOnSecurity because it gives more granular logging which is better for detection engineering.

Logs are collected through Azure Monitor Agent using a Data Collection Rule that targets the Microsoft-Windows-Sysmon/Operational channel. Everything flows into the LAW-PsychLab Log Analytics workspace in Sentinel.

<img width="1795" height="1061" alt="Screenshot 2026-04-20 124130" src="https://github.com/user-attachments/assets/42e19314-7466-447c-bcd8-9a6766e74a5a" />

Both machines are onboarded to Azure through Azure Arc since they are on-prem Hyper-V VMs and not Azure hosted.

<img width="1836" height="564" alt="Screenshot 2026-04-20 120239" src="https://github.com/user-attachments/assets/dec4f5ed-05d4-46d4-969d-759d271bf545" />

## Attack simulations

All attacks were run from WKS01 using Rubeus v2.2.0.

### Kerberoasting (T1558.003)

I ran `Rubeus.exe kerberoast` which queried LDAP for accounts with SPNs, found svc_sqlservice, requested a Kerberos service ticket, and extracted the RC4 hash. In a real scenario this hash would be cracked offline to get the service account password.

<img width="1525" height="1093" alt="Screenshot 2026-04-21 100908" src="https://github.com/user-attachments/assets/e676a37a-ec08-4d9b-a6a2-a47b034ffdf8" />

### AS-REP Roasting (T1558.004)

I ran `Rubeus.exe asreproast` which identified smitchell as having pre-auth disabled, sent an AS-REQ without credentials, and got back an AS-REP containing encrypted data that can be cracked offline.

<img width="1515" height="904" alt="Screenshot 2026-04-21 101853" src="https://github.com/user-attachments/assets/754ec7f7-ff15-45a2-9793-e3299446fbe0" />

### Kerberos ticket extraction (T1558)

I ran `Rubeus.exe dump /service:krbtgt /nowrap` to extract cached Kerberos tickets from the current logon session. In a real attack these could be used for Golden Ticket attacks.

<img width="1497" height="941" alt="Screenshot 2026-04-22 110805" src="https://github.com/user-attachments/assets/a4a78a86-b394-4e8c-892a-0c1b456af9da" />

## Detection rules

I wrote three custom analytics rules in Sentinel. Each one runs every 5 minutes with a 5 minute lookback window.

### Kerberoasting detection

```kql
Event
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 1
| extend EventData = parse_xml(EventData)
| extend CommandLine = tostring(EventData.DataItem.EventData.Data[10]["#text"])
| extend Image = tostring(EventData.DataItem.EventData.Data[4]["#text"])
| where CommandLine has "kerberoast" or CommandLine has "Invoke-Kerberoast" or Image has "Rubeus"
| project TimeGenerated, Computer, CommandLine, Image
```

### AS-REP Roasting detection

```kql
Event
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 1
| extend EventData = parse_xml(EventData)
| extend CommandLine = tostring(EventData.DataItem.EventData.Data[10]["#text"])
| extend Image = tostring(EventData.DataItem.EventData.Data[4]["#text"])
| where CommandLine has "asreproast" or CommandLine has "Invoke-ASREPRoast"
| project TimeGenerated, Computer, CommandLine, Image
```

### Kerberos ticket extraction detection

```kql
Event
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 1
| extend EventData = parse_xml(EventData)
| extend CommandLine = tostring(EventData.DataItem.EventData.Data[10]["#text"])
| extend Image = tostring(EventData.DataItem.EventData.Data[4]["#text"])
| where CommandLine has "dump" and (CommandLine has "krbtgt" or CommandLine has "ticket")
| project TimeGenerated, Computer, CommandLine, Image
```

All three are mapped to MITRE ATT&CK under Credential Access and they all generate High severity incidents when they fire.

<img width="1445" height="560" alt="image" src="https://github.com/user-attachments/assets/6caf2da8-6964-4d00-acd3-7e6ce1087c89" />

<img width="1853" height="1154" alt="Screenshot 2026-04-21 111004" src="https://github.com/user-attachments/assets/e557edd6-9811-4bad-96c9-a18b13d0b340" />

## Automated incident response

I built a Logic App playbook called PsychLab-IncidentNotification that triggers automatically whenever a High severity incident is created in Sentinel. It sends an email with the incident title, severity, status, description, and a direct link to the incident.
The full chain looks like this: attack gets executed, Sysmon captures the process creation event, Azure Monitor Agent forwards it to Sentinel, the analytics rule matches the activity, an incident gets created, the automation rule fires the Logic App, and I get an email.
The first time the email came through it was completely empty. The subject just said "PsychLab Alert: Incident" and the body had labels with no values next to them. The dynamic content fields in the Logic App were not properly mapped to the Sentinel incident trigger. I went back into the Logic App designer, deleted the body content, and rebuilt it by selecting each field directly from the Microsoft Sentinel incident trigger's dynamic content. After saving and running another attack the next email came through with everything populated: incident title, severity, status, description with the MITRE mapping, and a direct link to the incident in the Defender portal.

<img width="1348" height="379" alt="image" src="https://github.com/user-attachments/assets/ed4ff927-b375-49f7-9dd8-f50d07b33d7d" />

<img width="1422" height="670" alt="image" src="https://github.com/user-attachments/assets/f27d11e9-45fe-4659-8a73-02da7da69399" />

<img width="2989" height="517" alt="image" src="https://github.com/user-attachments/assets/1cbcc188-bf3a-46ef-afc7-71316ec0cad7" />


## SOC dashboard

I built a custom workbook in Sentinel with three panels. The first one is a time chart showing Sysmon event volume over the last 24 hours broken down by event ID. The second is a pie chart showing the distribution of events between DC01 and WKS01. The third is a grid showing all detected attack tool usage with timestamps, source machines, process images, and command lines.

<img width="1803" height="1783" alt="Screenshot 2026-04-22 163452" src="https://github.com/user-attachments/assets/f5290cb7-a877-4c0d-9d77-3611fc0ceb9b" />

## Defender for Cloud

Defender for Cloud is enabled with the Servers plan covering both Arc-enrolled machines. Foundational CSPM provides continuous security posture assessment.


## MITRE ATT&CK coverage

| Technique | ID | Tactic | Detection |
|-----------|-----|--------|-----------|
| Kerberoasting | T1558.003 | Credential Access | Sentinel analytics rule |
| AS-REP Roasting | T1558.004 | Credential Access | Sentinel analytics rule |
| Steal or Forge Kerberos Tickets | T1558 | Credential Access | Sentinel analytics rule |

## Tools

Hyper-V, Windows Server 2022, Windows 11 Enterprise, Active Directory Domain Services, DNS, Sysmon v15.20, sysmon-modular config, Microsoft Sentinel, Azure Monitor Agent, Azure Arc, Rubeus v2.2.0, Azure Logic Apps, Azure Workbooks, Microsoft Defender for Cloud, KQL.

## What I learned

Azure Arc is the bridge between on-prem and cloud security. Without it there is no way to get these Hyper-V machines into Sentinel without setting up expensive log forwarders or running everything in Azure VMs.

Sysmon with a proper config is everything. The sysmon-modular config gave me the telemetry depth I needed to catch attack tools at the process creation level. Without Sysmon these attacks would have been completely invisible to Sentinel.

Detection rules are only as good as the telemetry feeding them. Every rule I wrote depends on Sysmon Event ID 1 with command line logging. If any part of the chain breaks (Sysmon config, data collection rule, Azure Monitor Agent) the detections break too.

A detection that creates an incident but tells nobody is almost as useless as no detection at all. The Logic App playbook closes the loop by making sure I get notified immediately when something fires.

## Repo structure

```
PsychLab/
├── README.md
├── architecture/
│   └── lab-architecture.png
├── sysmon/
│   └── deployment-notes.md
├── analytics-rules/
│   ├── kerberoasting-detection.kql
│   ├── asrep-roasting-detection.kql
│   └── ticket-extraction-detection.kql
├── playbooks/
│   └── incident-notification.md
├── workbooks/
│   └── soc-dashboard.md
└── screenshots/
    ├── lab-architecture.png
    ├── azure-arc-connected.png
    ├── sysmon-telemetry.png
    ├── kerberoast-attack.png
    ├── asrep-attack.png
    ├── ticket-extraction.png
    ├── kql-detection.png
    ├── analytics-rules.png
    ├── sentinel-incidents.png
    ├── logic-app-playbook.png
    ├── automation-rule.png
    ├── email-notification.png
    ├── soc-dashboard.png
    └── defender-for-cloud.png
```

## Author

**Chukwuebuka Okorie**
- GitHub: [github.com/EbukaOkorie](https://github.com/EbukaOkorie)
- LinkedIn: [linkedin.com/in/chukwuebuka-okorie](https://www.linkedin.com/in/chukwuebuka-okorie-5132b2355/)
