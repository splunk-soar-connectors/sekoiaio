[comment]: # "Auto-generated SOAR connector documentation"
# Sekoia

Publisher: SEKOIA.IO  
Connector Version: 1.0.1  
Product Vendor: SEKOIA.IO  
Product Name: sekoia.io  
Product Version Supported (regex): ".\*"  
Minimum Product Version: 6.1.1.211  

This app will interact with SEKOIA.IO

# Splunk> Phantom

Welcome to the open-source repository for Splunk> Phantom's sekoiaio App.

Please have a look at our [Contributing Guide](https://github.com/Splunk-SOAR-Apps/.github/blob/main/.github/CONTRIBUTING.md) if you are interested in contributing, raising issues, or learning more about open-source Phantom apps.

## Legal and License

This Phantom App is licensed under the Apache 2.0 license. Please see our [Contributing Guide](https://github.com/Splunk-SOAR-Apps/.github/blob/main/.github/CONTRIBUTING.md#legal-notice) for further details.


### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a sekoia.io asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**base_url** |  required  | string | The SEKOIA API base url
**api_key** |  required  | password | The SEKOIA API key
**verify_server_cert** |  optional  | boolean | Verify server SSL (Default: true)

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration  
[get indicator](#action-get-indicator) - Get an indicator according to some criteria  
[get indicator context](#action-get-indicator-context) - Get the context of an indicator  
[get observable](#action-get-observable) - Get an observable according to some criteria  

## action: 'test connectivity'
Validate the asset configuration for connectivity using supplied configuration

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'get indicator'
Get an indicator according to some criteria

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**value** |  optional  | Value of the indicator | string | 
**type** |  optional  | Type of the indicator | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.value | string |  |  
action_result.parameter.type | string |  |  
action_result.status | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |  
action_result.data | string |  |  
action_result.summary.num_data | numeric |  |    

## action: 'get indicator context'
Get the context of an indicator

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**value** |  optional  | Value of the indicator | string | 
**type** |  optional  | Type of the indicator | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.value | string |  |  
action_result.parameter.type | string |  |  
action_result.status | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |  
action_result.data | string |  |  
action_result.summary.num_data | numeric |  |    

## action: 'get observable'
Get an observable according to some criteria

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**value** |  optional  | Value of the indicator | string | 
**type** |  optional  | Type of the indicator | string | 
**limit** |  optional  | Set the limit of items (Default:20) | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.value | string |  |  
action_result.parameter.type | string |  |  
action_result.parameter.limit | numeric |  |  
action_result.status | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |  
action_result.data | string |  |  
action_result.summary.num_data_get_observable | numeric |  |  