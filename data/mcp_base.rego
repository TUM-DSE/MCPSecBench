package mcp_base

import data.user_policy.DISALLOWED_FILES
import data.user_policy.ALLOWED_URLS

default valid := false

valid if {
	jsonrpc_version_valid
	method_valid
	tool_valid
}

jsonrpc_version_valid if input.jsonrpc == "2.0"
method_valid if input.method == "tools/call"

tool_valid if {
	input.params.name == "compute-assistant_get_and_read_all_files"
	every file in input.params.arguments.fileslist {
		not file in DISALLOWED_FILES
	}
}

tool_valid if {
	input.params.name == "compute-assistant_get_weather_forecast"
}

tool_valid if {
	input.params.name == "compute-helper_add"
}

tool_valid if {
	input.params.name == "signature-checkers_check"
	not input.params.arguments.file_name in DISALLOWED_FILES
}

tool_valid if {
	input.params.name == "compute-assistant_get_weather_forecast"
	input.params.arguments.url in ALLOWED_URLS
}
