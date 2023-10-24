#!/usr/bin/python
# -*- coding: utf-8 -*-

# Python 3 Compatibility imports
from __future__ import print_function, unicode_literals

import json

# Phantom App imports
import phantom.app as phantom
# Useful libraries
import requests
from bs4 import BeautifulSoup
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector

# Usage of the consts file is recommended
from sekoiaio_consts import (DOCUMENTATION_LOG, EMPTY_RESPONSE_ERROR_LOG, JSON_RESPONSE_400_ERROR_LOG, JSON_RESPONSE_401_ERROR_LOG,
                             JSON_RESPONSE_403_ERROR_LOG)


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class SekoiaioConnector(BaseConnector):
    def __init__(self):
        super(SekoiaioConnector, self).__init__()
        self._state = None
        self._base_url = None
        self.api_key = None

    def initialize(self):
        """
        This's an optinal method but we will use it to load
        both state and configuration
        """
        self._state = self.load_state()
        config = self.get_config()
        self._base_url = config["base_url"]
        self.api_key = config["api_key"]

        if not (self._base_url or self.api_key):
            return phantom.APP_ERROR

        return phantom.APP_SUCCESS

    def finalize(self):
        """
        Save the state, this data is saved across actions and app upgrades
        """
        self.save_state(self._state)
        return phantom.APP_SUCCESS

    def _process_empty_response(self, response, action_result):
        """
        How we can process an empty response for both 200 and for >400
        """
        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(
            action_result.set_status(phantom.APP_ERROR, EMPTY_RESPONSE_ERROR_LOG), None
        )

    def _process_html_response(self, response, action_result):
        """
        How we can process an HTML response
        """
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            error_text = soup.text
            split_lines = error_text.split("\n")
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = "\n".join(split_lines)
        except Exception as e:
            error_text = f"Cannot parse error details : {e}"

        message = "Status Code: {0}. Data from server:\n{1}\n".format(
            status_code, error_text
        )

        message = message.replace("{", "{{").replace("}", "}}")
        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, response, action_result):
        """
        How we can process an JSON response
        """
        try:
            resp_json = response.json()
        except Exception as e:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR,
                    "Unable to parse JSON response. Error: {0}".format(str(e)),
                ),
                None,
            )

        if 200 <= response.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        if response.status_code == 400:
            return action_result.set_status(
                phantom.APP_ERROR, JSON_RESPONSE_400_ERROR_LOG
            )

        if response.status_code == 401:
            return action_result.set_status(
                phantom.APP_ERROR, JSON_RESPONSE_401_ERROR_LOG
            )

        if response.status_code == 403:
            return action_result.set_status(
                phantom.APP_ERROR, JSON_RESPONSE_403_ERROR_LOG
            )

        message = "Error from server. Status Code: {0} \
                Data from server: {1}".format(
            response.status_code, response.text.replace("{", "{{").replace("}", "}}")
        )

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, response, action_result):
        """
        The main method to process a Response.
        In our case there are just JSON reponses
        """
        if hasattr(action_result, "add_debug_data"):
            action_result.add_debug_data({"response_status_code": response.status_code})
            action_result.add_debug_data({"response_text": response.text})
            action_result.add_debug_data({"response_headers": response.headers})

        if "json" in response.headers.get("Content-Type", ""):
            return self._process_json_response(response, action_result)

        if "html" in response.headers.get("Content-Type", ""):
            return self._process_html_response(response, action_result)

        if not response.text:
            return self._process_empty_response(response, action_result)

        message = "Can't process response from server. \
            Status Code: {0} Data from server: {1}".format(
            response.status_code, response.text.replace("{", "{{").replace("}", "}}")
        )

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, endpoint, action_result, method="get", **kwargs):
        """
        This's for making rest calls depending on the method choosen.
        """
        config = self.get_config()
        resp_json = None
        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, "Invalid method: {0}".format(method)
                ),
                resp_json,
            )
        url = self._base_url + endpoint
        try:
            response = request_func(
                url, verify=config.get("verify_server_cert", False), **kwargs
            )
        except requests.exceptions.InvalidURL:
            error_message = f"Error connecting to server. Invalid URL: {url}"
            return RetVal(
                action_result.set_status(phantom.APP_ERROR, error_message), resp_json
            )
        except requests.exceptions.InvalidSchema:
            error_message = f"Error connecting to server. \
                No connection adapters were found for {url}"
            return RetVal(
                action_result.set_status(phantom.APP_ERROR, error_message), resp_json
            )
        except requests.exceptions.ConnectionError:
            error_message = f"Error connecting to server. \
                Connection Refused from the Server for {url}"
            return RetVal(
                action_result.set_status(phantom.APP_ERROR, error_message), resp_json
            )
        except Exception as e:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR,
                    "Error Connecting to server. Details: {0}".format(str(e)),
                ),
                resp_json,
            )

        return self._process_response(response, action_result)

    def _handle_test_connectivity(self, param):
        """
        Tests API connectivity and authentication
        """
        action_result = self.add_action_result(ActionResult(dict(param)))
        self.save_progress("Start Connecting to endpoint ..... !!")
        headers = {"Authorization": "Bearer {0}".format(self.api_key)}
        ret_val, response = self._make_rest_call(
            "/v1/auth/validate", action_result, params=None, headers=headers
        )

        if phantom.is_fail(ret_val):
            self.save_progress(f"Test Connectivity Failed. {DOCUMENTATION_LOG}")
            return action_result.get_status()

        self.save_progress(
            "Test connectivity passed, your token is valid. You can use it."
        )
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_indicator(self, param):
        """
        Create an action that allow the user to
        get an indicator according to some criteria
        """
        self.save_progress(
            "In get indicator action handler for: {0}".format(
                self.get_action_identifier()
            )
        )
        action_result = self.add_action_result(ActionResult(dict(param)))

        # This 2 required parameters to requests this endpoint
        # Take a look at
        # /cti/develop/rest_api/intelligences/Indicators
        value, _type = param.get("value", ""), param.get("type", "")
        params, headers = {"value": value, "type": _type}, {
            "Authorization": "Bearer {0}".format(self.api_key)
        }
        ret_val, response = self._make_rest_call(
            "/v2/inthreat/indicators", action_result, params=params, headers=headers
        )

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        self.save_progress("Great, we get response from the endpoint !!")
        # Add the response into the data section
        action_result.add_data(response.get("items", []))

        # Add a dictionary that is made up of the
        # most important values from data into the summary
        summary = action_result.update_summary({})
        summary["num_data"] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_indicator_context(self, param):
        """
        Create an action that allow the user to
        get the context of an indicator.
        """
        self.save_progress(
            "In get indicator context action handler for: {0}".format(
                self.get_action_identifier()
            )
        )
        action_result = self.add_action_result(ActionResult(dict(param)))

        # This 2 required parameters to requests this endpoint
        # Take a look at
        # cti/develop/rest_api/intelligence/Indicators/operation/get_indicator_context_resource
        value, _type = param.get("value", ""), param.get("type", "")
        params, headers = {"value": value, "type": _type}, {
            "Authorization": "Bearer {0}".format(self.api_key)
        }
        ret_val, response = self._make_rest_call(
            "/v2/inthreat/indicators/context",
            action_result,
            params=params,
            headers=headers,
        )

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        self.save_progress("Great, we get response from the endpoint !!")

        action_result.add_data(response)

        # Add a dictionary that is made up of
        # the most important values from data into the summary
        summary = action_result.update_summary({})
        summary["num_data"] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_observable(self, param):
        """
        Create an action that allow the user to
        get an observable according to some criteria
        """
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )
        action_result = self.add_action_result(ActionResult(dict(param)))

        value, _type, limit = (
            param.get("value", ""),
            param.get("type", ""),
            param.get("limit", ""),
        )
        params, headers = {"value": value, "type": _type, "limit": limit}, {
            "Authorization": "Bearer {0}".format(self.api_key)
        }
        # make rest call
        ret_val, response = self._make_rest_call(
            "/v2/inthreat/observables", action_result, params=params, headers=headers
        )

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        self.save_progress("Great, we get response from the endpoint !!")

        # Add the response into the data section
        action_result.add_data(response.get("items", []))

        # Add a dictionary that is made up of the
        # most important values from data into the summary
        summary = action_result.update_summary({})
        summary["num_data_get_observable"] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):
        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == "get_indicator":
            ret_val = self._handle_get_indicator(param)

        if action_id == "get_indicator_context":
            ret_val = self._handle_get_indicator_context(param)

        if action_id == "get_observable":
            ret_val = self._handle_get_observable(param)

        if action_id == "test_connectivity":
            ret_val = self._handle_test_connectivity(param)

        return ret_val


def main():
    import argparse

    argparser = argparse.ArgumentParser()

    argparser.add_argument("input_test_json", help="Input Test JSON file")
    argparser.add_argument("-u", "--username", help="username", required=False)
    argparser.add_argument("-p", "--password", help="password", required=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password

    if username is not None and password is None:
        # User specified a username but not a password, so ask
        import getpass

        password = getpass.getpass("Password: ")

    if username and password:
        try:
            login_url = SekoiaioConnector._get_phantom_base_url() + "/login"

            print("Accessing the Login page")
            r = requests.get(login_url, verify=False)
            csrftoken = r.cookies["csrftoken"]

            data = dict()
            data["username"] = username
            data["password"] = password
            data["csrfmiddlewaretoken"] = csrftoken

            headers = dict()
            headers["Cookie"] = "csrftoken=" + csrftoken
            headers["Referer"] = login_url

            print("Logging into Platform to get the session id")
            r2 = requests.post(login_url, verify=False, data=data, headers=headers)
            session_id = r2.cookies["sessionid"]
        except Exception as e:
            print(
                "Unable to get session id \
                from the platform. Error: " + str(e)
            )
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = SekoiaioConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json["user_session_token"] = session_id
            connector._set_csrf_info(csrftoken, headers["Referer"])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)


if __name__ == "__main__":
    main()
