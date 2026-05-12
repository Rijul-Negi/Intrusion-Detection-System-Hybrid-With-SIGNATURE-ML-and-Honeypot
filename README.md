# Intrusion Detection System Hybrid(SIGNATURE + ML) and Honeypot

## Table of Contexts

## What is the Project?

- An Intrusion Detection System is a tool that is commonly used to monitor the traffic and send Alerts/Information on potentially suspicious
  behavior and the appropriate source.
- A Honeypot is a "trap" of sorts, which is often used in order to identify and catch malicious users while avoiding non-malicious ones.
  By creating a fake target/decoy that would not normally be accessed or interacted with. It can reveal malicious attempts cause harm to an
  organization and it's infrastructure  

Intrusion Detection Systems come in a few flavors:-
  1. Signature based
  2. Anomaly based
  3. Hybrid [Consisting of both Signature and Anomaly]

This Project is Hybrid, consisting of both a trained model and signature (by parsing the ruleset) based detection.
Furthermore, Port Honeypots are used and personally configurable with the specific port and banner for each port.

## Tech Stack

### Programming Languages
- Python
- HTML
- CSS

### Machine Learning & Data Processing
- XGBoost
- Pandas

### Networking & Comms
- Scapy
- Socket Programming

### Web Framework
- Flask

### System Monitoring
- Psutil

### Concurrency - Multithreading
- Python Threading

### Data Format
- JSON

## Features

## Dependencies

## Working Demonstration

## Credits
NF-UNSW-NB15-v3 and NF-ToN-IoT-v3 datasets:

```
@misc{luay2025NetFlowDatasetsV3,
title = {Temporal Analysis of NetFlow Datasets for Network Intrusion Detection Systems},
author = {Majed Luay and Siamak Layeghy and Seyedehfaezeh Hosseininoorbin and Mohanad Sarhan and Nour Moustafa and Marius Portmann},
year = {2025},
eprint = {2503.04404},
archivePrefix= {arXiv},\
primaryClass = {cs.LG},
url = {https://arxiv.org/abs/2503.04404}
}
```

CIC-DDoS2019
```
Dr. Iman Sharafaldin, Dr. Saqib Hakak, Dr. Arash Habibi Lashkari Dr. Ali Ghorbani. 
https://ieeexplore.ieee.org/abstract/document/8888419
```
