<h1 align="center">
smartshield v1.1.16


# Table of Contents

- [Introduction](#introduction)
- [Usage](#usage)
- [GUI](#graphical-user-interface)
- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration](#configuration)
- [Features](#features)
- [Contributing](#contributing)
- [Documentation](#documentation)
- [Troubleshooting](#troubleshooting)
- [License](#license)
- [Credits](#credits)
- [Changelog](#changelog)
- [Roadmap](#roadmap)
- [Demos](#demos)
- [Funding](#funding)


# smartshield: Behavioral Machine Learning-Based Intrusion Prevention System


smartshield is a powerful endpoint behavioral intrusion prevention and detection system that uses machine learning to detect malicious behaviors in network traffic. smartshield can work with network traffic in real-time, PCAP files, and network flows from popular tools like Suricata, Zeek/Bro, and Argus. smartshield threat detection is based on a combination of machine learning models trained to detect malicious behaviors, 40+ threat intelligence feeds, and expert heuristics. smartshield gathers evidence of malicious behavior and uses extensively trained thresholds to trigger alerts when enough evidence is accumulated.

<img src="https://raw.githubusercontent.com/stratosphereips/StratosphereLinuxIPS/develop/docs/images/smartshield.gif" width="850px" title="smartshield in action.">

---


# Introduction
smartshield is the first free software behavioral machine learning-based IDS/IPS for endpoints. It was created in 2012 by Sebastian Garcia at the Stratosphere Laboratory, AIC, FEE, Czech Technical University in Prague. The goal was to offer a local IDS/IPS that leverages machine learning to detect network attacks using behavioral analysis.


smartshield is supported on Linux, MacOS, and windows dockers only. The blocking features of smartshield are only supported on Linux

smartshield is Python-based and relies on [Zeek network analysis framework](https://zeek.org/get-zeek/) for capturing live traffic and analyzing PCAPs. and relies on
Redis >= 7.0.4 for interprocess communication.

---

# Usage

The recommended way to use smartshield is on Docker.

#### Linux and Windows hosts
```
docker run --rm -it -p 55000:55000  --cpu-shares "700" --memory="8g" --memory-swap="8g" --net=host --cap-add=NET_ADMIN --name smartshield stratosphereips/smartshield:latest
```

```
./smartshield.py -f dataset/test7-malicious.pcap -o output_dir
```

```
cat output_dir/alerts.log
```

#### Macos
In MacOS, do not use --net=host if you want to access the internal container's ports from the host.

```
docker run --rm -it -p 55000:55000 --platform linux/amd64 --cpu-shares "700" --memory="8g" --memory-swap="8g" --cap-add=NET_ADMIN --name smartshield stratosphereips/smartshield_macos_m1:latest
```

```
./smartshield.py -f dataset/test7-malicious.pcap -o output_dir
```

```
cat output_dir/alerts.log
```


[For more installation options](https://stratospherelinuxips.readthedocs.io/en/develop/installation.html#installation)

[For a detailed explanation of smartshield parameters](https://stratospherelinuxips.readthedocs.io/en/develop/usage.html#smartshield-parameters)

---


# Graphical User Interface

To check smartshield output using a GUI you can use the web interface
or our command-line based interface Kalipso

##### Web interface

    ./webinterface.sh

Then navigate to ```http://localhost:55000/``` from your browser.

<img src="https://raw.githubusercontent.com/stratosphereips/StratosphereLinuxIPS/develop/docs/images/web_interface.png" width="850px">

For more info about the web interface, check the docs: https://stratospherelinuxips.readthedocs.io/en/develop/usage.html#the-web-interface


##### Kalipso (CLI-Interface)

    ./kalipso.sh

<img src="https://raw.githubusercontent.com/stratosphereips/StratosphereLinuxIPS/develop/docs/images/kalipso.png" width="850px">


For more info about the Kalipso interface, check the docs: https://stratospherelinuxips.readthedocs.io/en/develop/usage.html#kalipso

---


# Requirements

smartshield requires Python 3.10.12 and at least 4 GBs of RAM to run smoothly.

---

# Installation


smartshield can be run on different platforms, the easiest and most recommended way if you're a Linux user is to run smartshield on Docker.

* [Docker](https://stratospherelinuxips.readthedocs.io/en/develop/installation.html#smartshield-in-docker)
  * Dockerhub (recommended)
    * [Linux and windows hosts](https://stratospherelinuxips.readthedocs.io/en/develop/installation.html#linux-and-windows-hosts)
    * [MacOS hosts](https://stratospherelinuxips.readthedocs.io/en/develop/installation.html#macos-hosts)
  * [Docker-compose](https://stratospherelinuxips.readthedocs.io/en/develop/installation.html#running-smartshield-using-docker-compose)
  * [Dockerfile](https://stratospherelinuxips.readthedocs.io/en/develop/installation.html#building-smartshield-from-the-dockerfile)
* Native
  * [Using install.sh](https://stratospherelinuxips.readthedocs.io/en/develop/installation.html#install-smartshield-using-shell-script)
  * [Manually](https://stratospherelinuxips.readthedocs.io/en/develop/installation.html#installing-smartshield-manually)
* [on RPI (Beta)](https://stratospherelinuxips.readthedocs.io/en/develop/installation.html#installing-smartshield-on-a-raspberry-pi)


---


# Configuration
smartshield has a [config/smartshield.yaml](https://github.com/stratosphereips/StratosphereLinuxIPS/blob/develop/config/smartshield.yaml) that contains user configurations for different modules and general execution.

* You can change the timewindow width by modifying the ```time_window_width``` parameter
* You can change the analysis direction to ```all```  if you want to see the attacks from and to your computer
* You can also specify whether to ```train``` or ```test``` the ML models

* You can enable [popup notifications](https://stratospherelinuxips.readthedocs.io/en/develop/usage.html#popup-notifications) of evidence, enable [blocking](https://stratospherelinuxips.readthedocs.io/en/develop/usage.html#smartshield-permissions), [plug in your own zeek script](https://stratospherelinuxips.readthedocs.io/en/develop/usage.html#plug-in-a-zeek-script) and more.


[More details about the config file options here]( https://stratospherelinuxips.readthedocs.io/en/develop/usage.html#modifying-the-configuration-file)

---

# Features
smartshield key features are:

* **Behavioral Intrusion Prevention**: smartshield acts as a powerful system to prevent intrusions based on detecting malicious behaviors in network traffic using machine learning.
* **Modularity**: smartshield is written in Python and is highly modular with different modules performing specific detections in the network traffic.
* **Targeted Attacks and Command & Control Detection**: It places a strong emphasis on identifying targeted attacks and command and control channels in network traffic.
* **Traffic Analysis Flexibility**: smartshield can analyze network traffic in real-time, PCAP files, and network flows from popular tools like Suricata, Zeek/Bro, and Argus.
* **Threat Intelligence Updates**: smartshield continuously updates threat intelligence files and databases, providing relevant detections as updates occur.
* **Integration with External Platforms**: Modules in smartshield can look up IP addresses on external platforms such as VirusTotal and RiskIQ.
* **Graphical User Interface**: smartshield provides a console graphical user interface (Kalipso) and a web interface for displaying detection with graphs and tables.
* **Peer-to-Peer (P2P) Module**: smartshield includes a complex automatic system to find other peers in the network and share IoC data automatically in a balanced, trusted manner. The P2P module can be enabled as needed.
* **Docker Implementation**: Running smartshield through Docker on Linux systems is simplified, allowing real-time traffic analysis.
* **Detailed Documentation**: smartshield provides detailed documentation guiding users through usage instructions for efficient utilization of its features.
* **Federated learning** Using the feel_project submodule. for more information [check the docs](https://github.com/stratosphereips/feel_project/blob/main/docs/Federated_Learning.md)

---

# Contributing

We welcome contributions to improve the functionality and features of smartshield.

Please read carefully the [contributing guidelines](https://stratospherelinuxips.readthedocs.io/en/develop/contributing.html) for contributing to the development of smartshield

You can run smartshield and report bugs, make feature requests, and suggest ideas, open a pull request with a solved GitHub issue and new feature, or open a pull request with a new detection module.

The instructions to create a new detection module along with a template [here](https://stratospherelinuxips.readthedocs.io/en/develop/create_new_module.html).

If you are a student, we encourage you to apply for the Google Summer of Code program that we participate in as a hosting organization.

Check [smartshield in GSoC2023](https://github.com/stratosphereips/Google-Summer-of-Code-2023) for more information.


You can [join our conversations in Discord](https://discord.gg/zu5HwMFy5C) for questions and discussions.
We appreciate your contributions and thank you for helping to improve smartshield!

---

# Documentation
[User documentation](https://stratospherelinuxips.readthedocs.io/en/develop/)

[Code docs](https://stratospherelinuxips.readthedocs.io/en/develop/code_documentation.html )

---

# Troubleshooting

If you can't listen to an interface without sudo, foe example when zeek is throwing the following error:
```bash
fatal error: problem with interface wlan0 (pcap_error: socket: Operation not permitted (pcap_activate))
```

you can adjust zeek capabilities using the following command

```
sudo setcap cap_net_raw,cap_net_admin=eip /<path-to-zeek-bin/zeek
```

