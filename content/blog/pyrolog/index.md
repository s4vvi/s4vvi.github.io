+++
title = 'Pyrolog'
date = 2022-10-12T21:12:03+02:00
draft = false
tags = ['tool', 'special', 'github']
summary = 'One my first programming projects. "PyroLog" is a simple log remover written in Python.'
description = 'One my first programming projects. "PyroLog" is a simple log remover written in Python.'
thumbnail = 'img/pl-logo.png'
+++

# Pyrolog
## Overview
[PyroLog](https://github.com/s4vvi/PyroLog) is an effective but also a simple log cleaner. This is a tool that can be used to clear your tracks as a pen-tester or just clean a computer. PyroLog is currently only available on Linux and requires python3.

![screenshot](https://i.imgur.com/6HwBSP6.jpg)

*(No dependencies)*

## Help Menu

```text
usage: pyrolog.py [-h] --method METHOD --scope SCOPE [OPTIONS]

Required options:
  -h, --help       Show this help message!
  --method METHOD  Select a method to use. Available methods:
                   1. delete    | Permanently deletes target/log files;
                   2. clear     | Fills target/log files with null values. Files themselves remain;
  --scope SCOPE    Select the removal scope. Format: "option,option".
                   Available options:
                   1. all       | Select all of the options (Dangerous);
                   2. files     | Use the wordlist with common log files;
                   3. dirs      | Select a wordlist of directories to recursively remove files in;
                   4. custom    | Select a custom wordlist, or include/exclude files from the default lists;
                   5. home      | Remove predefined history/log files in home directories;

Custom wordlist options:
  -af PATH         Append extra log/target files to the set wordlist.
  -ad PATH         Append extra log/target directories to the directory list.
  -rf PATH         Remove specific log/target files from the wordlist.
  -rd PATH         Remove specific log/target directories from the directory list.
  --loglist PATH   Use a custom wordlist of logfiles to clear.
  --dirlist PATH   Use a custom wordlist of directories to clear.
```

Basic usage:
```bash
sudo pyrolog.py --method clear --scope all
```
