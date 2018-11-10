# pygeddon

A project to create a multi platform python script with features such as deauthing networks, recognising deauth frames and other network attacks/defences.

# Current Features

Can deauth single or multiple networks at once but still needs the channel to be manually selected using other software like aireplay-ng. Unless on OSX where channel can be specified when running the script. Also has a built in sniffer for finding target AP's or a manual option to input the AP's MAC address. (deauth.py)

Can detect deauth frames and display a basic overview of the deauth packet. (deauth-detect.py)

# Planned Features

Client discovery
Tracking which networks devices are on
Use client tracking to deauth a device on whichever networks it tries to connect to 😂.
