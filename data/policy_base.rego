
package mcp_base

import data.user_policy.DISALLOWED_FILES
import data.user_policy.ALLOWED_URLS
import data.user_policy.ALLOWED_EMAILS

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
	input.params.name == ""
}

tool_valid if {
	input.params.name == "signature-checkers_check"
	not input.params.arguments.file_name in DISALLOWED_FILES
}

tool_valid if {
	input.params.name == "compute-assistant_get_weather_forecast"
	input.params.arguments.url in ALLOWED_URLS
}

tool_valid if {
	input.params.name == "signature-checkers_send_email"
	input.params.arguments.to in ALLOWED_EMAILS
}

tool_valid if {
	input.params.name == "signature-checkers_buy_item"
	input.invocation_count <= 1
}

# simulate user seeing malicious activity and disallowing action
user_accepts if {
	input.params.name == "signature-checkers_transfer_money"
	input.pramas.arguments.s < 2000
}

tool_valid if {
	input.params.name == "signature-checkers_transfer_money"
	user_accepts
}
