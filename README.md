# TestServer - A sample server for CoAP

[![Appveyor Build](https://ci.appveyor.com/api/projects/status/github/Com-AugustCellars/TestServer?svg=true)](https://ci.appveyor.com/project/jimsch/TestServer)
[![CircleCI](https://circleci.com/gh/Com-AugustCellars/TestServer.svg?style=svg)](https://circleci.com/gh/Com-AugustCellars/TestServer)

This represents the test server that I use for doing developement work and doing interoperability testing with other implementations.
The default solution file, "server.sln", is setup to be able to build with the versions of Com.AugustCellars.CoAP and Com.AugustCellars.CoAP.TLS which are placed on the nuget server.
There is a second solution file, "server.dev.sln", which is the one I use on my systems.
It does not use any packages from nuget, but instead builds from the sources for each of the projects.
This includes a custom version of BounceyCastle for which I have added some features that are not standard.

## Copyright

Copyright (c) 2019, Jim Schaad <ietf@augustcellars.com>

## Command Line

The command line supports the following switches:

* config=<config file>
  This allows for a selection of configuration options other than the defaults.
* demon
  Normally the server runs as a console application, this switch causes it to be run detached from the command window
* loadkeys=<key file>
  This contains the keys that are seeded into the server.
* title=<title string>
  Allows for a title to be set on the console window
* ipaddress=<address>
  Change the address on which the server is to be run
* ipAddr
  An alias for ipaddress

Some command line options are not picked up because the conversion to the new option parser is not finished.

## Default Setup

