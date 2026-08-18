from ide_scanner.value_flow import credential_value_flow


def test_identifier_lineage_reaches_network_body():
    flow = credential_value_flow(
        "const secret=fs.readFileSync(home+'/.ssh/id_ed25519');"
        "const payload=JSON.stringify(secret);const body=payload;req.write(body);"
    )
    assert flow is not None
    assert flow["variable_path"] == ["secret", "payload", "body"]
    assert flow["sink_variable"] == "body"
    assert flow["transformed"] is True


def test_unrelated_network_body_is_not_tainted():
    assert credential_value_flow(
        "const secret=fs.readFileSync(home+'/.npmrc');"
        "const telemetry=JSON.stringify({event:'open'});req.write(telemetry);"
    ) is None


def test_ordinary_file_read_is_not_credential_source():
    assert credential_value_flow(
        "const source=fs.readFileSync(workspace+'/package.json');req.write(source);"
    ) is None


def test_direct_tainted_value_is_detected_without_transform():
    flow = credential_value_flow(
        "const key=fs.readFileSync(home+'/.aws/credentials');req.write(key);"
    )
    assert flow is not None
    assert flow["variable_path"] == ["key"]
    assert flow["transformed"] is False


def test_taint_flows_through_function_parameter_to_network_sink():
    flow = credential_value_flow(
        "function transmit(data){const req=https.request(options);req.write(data)}"
        "const secret=fs.readFileSync(home+'/.ssh/id_ed25519');transmit(secret);"
    )
    assert flow is not None
    assert flow["correlation"] == "same-file-function-parameter-value-flow"
    assert flow["function"] == "transmit"
    assert flow["parameter"] == "data"
    assert flow["variable_path"] == ["secret", "transmit:data"]


def test_unrelated_function_argument_does_not_taint_network_sink():
    assert credential_value_flow(
        "function transmit(data){req.write(data)}"
        "const secret=fs.readFileSync(home+'/.npmrc');transmit(telemetry);"
    ) is None


def test_function_with_unused_parameter_is_not_a_sink():
    assert credential_value_flow(
        "function log(data){console.log('event')}"
        "const secret=fs.readFileSync(home+'/.aws/credentials');log(secret);"
    ) is None


def test_object_property_preserves_credential_taint():
    flow = credential_value_flow(
        "const collected={};const key=fs.readFileSync(home+'/.ssh/id_ed25519');"
        "collected.sshKey=key;const body=JSON.stringify(collected);req.write(body);"
    )
    assert flow is not None
    assert flow["variable_path"] == ["key", "collected.sshKey", "collected", "body"]


def test_unrelated_object_property_does_not_taint_container():
    assert credential_value_flow(
        "const collected={};const key=fs.readFileSync(home+'/.npmrc');"
        "collected.event=telemetry;req.write(JSON.stringify(collected));"
    ) is None


def test_sink_before_credential_read_is_not_a_flow():
    assert credential_value_flow(
        "req.write(secret);const secret=fs.readFileSync(home+'/.aws/credentials');"
    ) is None


def test_alias_before_source_assignment_is_not_tainted_retroactively():
    assert credential_value_flow(
        "const body=secret;const secret=fs.readFileSync(home+'/.npmrc');req.write(body);"
    ) is None


def test_taint_flows_through_local_function_return():
    flow = credential_value_flow(
        "function encode(value){return JSON.stringify(value)}"
        "const secret=fs.readFileSync(home+'/.npmrc');const body=encode(secret);req.write(body);"
    )
    assert flow is not None
    assert flow["variable_path"] == ["secret", "encode:value:return", "body"]
    assert flow["transformed"] is True


def test_call_that_discards_secret_does_not_taint_return_value():
    assert credential_value_flow(
        "function validate(value){return true}"
        "const secret=fs.readFileSync(home+'/.npmrc');const ok=validate(secret);req.write(ok);"
    ) is None


def test_arbitrary_expression_containing_secret_is_not_assumed_tainted():
    assert credential_value_flow(
        "const secret=fs.readFileSync(home+'/.ssh/id_ed25519');"
        "const status=secret ? 'configured' : 'missing';req.write(status);"
    ) is None
