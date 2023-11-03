[comment]: # "File: README.md"
[comment]: # "Copyright (c) SEKOIA.IO, 2023"
[comment]: # ""
[comment]: # "Licensed under the Apache License, Version 2.0 (the 'License');"
[comment]: # "you may not use this file except in compliance with the License."
[comment]: # "You may obtain a copy of the License at"
[comment]: # ""
[comment]: # "    http://www.apache.org/licenses/LICENSE-2.0"
[comment]: # ""
[comment]: # "Unless required by applicable law or agreed to in writing, software distributed under"
[comment]: # "the License is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,"
[comment]: # "either express or implied. See the License for the specific language governing permissions"
[comment]: # "and limitations under the License."
[comment]: # ""
# Sekoia.io actions
## Purpose

Develop a Splunk SOAR App that interact with [SEKOIA.IO](http://SEKOIA.IO) CTI.

## Authentication

To interact with the [SEKOIA.IO](http://SEKOIA.IO) API, use an API key.

see [this documentation](https://docs.sekoia.io/cti/features/integrations/api/) for more information

## Actions

The App should implement the following actions

### Get indicator

This action  allow the user to get an indicator according to some criteria

### Get indicator Context

Create an action that allow the user to get the context of an indicator

### Get Observable

Create an action that allow the user to get an observable according to some criteria

## Port Information

The app uses HTTP/ HTTPS protocol for communicating with the Sekoiaio api. Below are the default
ports used by Splunk SOAR.

|         Service Name | Transport Protocol | Port |
|----------------------|--------------------|------|
|         http         | tcp                | 80   |
|         https        | tcp                | 443  |
