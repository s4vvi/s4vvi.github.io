+++
title = 'Crun'
date = 2024-08-11T17:04:22+03:00
draft = false
tags = ['tool', 'github', 'special']
summary = 'Rofi plugin for custom application running. Quickly run specific commands with out the use of desktop files.'
description = 'Rofi plugin for custom application running.'
thumbnail = 'img/cr-thumbnail.png'
+++

Crun - Custom run (For Rofi)
======================================

[Crun](https://github.com/s4vvi/crun) is a [Rofi](https://github.com/davatorium/rofi) plugin used to run custom applications. As opposed to desktop files, this allows quick configuration in `~/.config/rofi/crun.json` *(See provided sample configuration)*.

![](img/cr-terminal.png)

This plugin can be used to run various tools that would normally be run via terminal or the `run` Rofi module. The point is to avoid the `run` history or the repeated typing of long CLI commands.

Installation:
```bash
# Clone & compile the plugin
git clone https://github.com/s4vvi/crun.git
cd crun && cargo build

# Make directory for plugin library & configuration file
sudo mkdir /usr/lib/rofi
mkdir ~/.config/rofi

# Copy the library (plugin) & the configuration (example)
sudo cp target/debug/libcrun.so /usr/lib/rofi
cp crun.json ~/.config/rofi

# Run the plugin
rofi -show crun -modi crun
```

Example of the configuration file:
```json
[
    {
        "name": "YouTube",
        "bin": "/usr/bin/brave",
        "args": ["https://youtube.com"]
    },
    {
        "name": "GitHub",
        "bin": "/usr/bin/brave",
        "args": ["https://github.com"]
    },
    {
        "name": "AVD - Mobile",
        "bin": "/opt/android-sdk/emulator/emulator",
        "args": ["-avd", "mobile"]
    }
]
```

Note that for easy & quick access it can be bound to a shortcut. In the case of I3VM:
```text
bindsym $mod+s exec --no-startup-id rofi -modi crun -show crun -font 'Source Code Pro 12'
```
