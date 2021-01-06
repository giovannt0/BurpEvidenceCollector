# BurpEvidenceCollector

BurpEvidenceCollector is a plugin for Burp Suite. It allows you to send requests / responses to a new tab (dabbed 'Evidence Collector') and assign OWASP testing objectives to them.
It comes with a loaded CWE database for easy evidence sorting, evidence highlighting, and the possibility to export to a file your work and load it back at a later time for easy QA.

Get it here: https://github.com/giovannt0/BurpEvidenceCollector/releases/download/0.1/BurpEvidenceCollector-all.jar

<img width="1139" alt="Screenshot 2020-12-09 at 16 27 54" src="https://user-images.githubusercontent.com/25910997/101649464-31ec8e00-3a3b-11eb-8b1b-209af59a4fbc.png">

<img width="1281" alt="Screenshot 2020-12-09 at 15 37 25" src="https://user-images.githubusercontent.com/25910997/101649664-711adf00-3a3b-11eb-9790-f2164e465b6c.png">

<img width="1140" alt="Screenshot 2020-12-09 at 16 30 47" src="https://user-images.githubusercontent.com/25910997/101649837-9a3b6f80-3a3b-11eb-88be-50df9ef416f1.png">

## Building from source

`gradle build fatJar`

The jar will be in `build/libs/BurpEvidenceCollector-all.jar`

## Disclaimer

The project is currently not maintained. Should you find anything weird, feel free to send a PR!
