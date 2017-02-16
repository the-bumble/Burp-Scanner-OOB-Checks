Out-of-band Checks
============

This is a Burp extension for adding additional payloads to active scanner that require out-of-band validation.

![Out-of-band Checks](/demo.png?raw=true)

## Installation

#### Jython Setup
 1. Download the latest standalone [Jython 2.7.x](http://www.jython.org/downloads.html) .jar file
 1. In Burp select `Extender` and then the `Options` tab, under the _Python Environment_ heading click `Select File ...` and browse to the Jython .jar file

#### Out-of-bound Checks Plugin Setup
 1. In Burp select `Extender` and then the `Extensions` tab
 1. Click `Add` in the window that appears, select `Python` from the `Extension Type` dropdown menu
 1. Click `Select File ...` next to `Extension File` and select `oob-plugin.py` file
 1. Click `Next` and an `OOB` tab will appear
 1. Navigate to the `OOB` tab and add payloads as you would in Intruder
