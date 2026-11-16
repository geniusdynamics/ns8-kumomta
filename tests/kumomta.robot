*** Settings ***
Library    SSHLibrary
Library    Collections

*** Variables ***
# Names under the reserved .test TLD: nothing resolves them
${TEST_HOST}       mx.ns8-ci.test
${TEST_DOMAIN}     ns8-ci.test
# Inbound route to TEST-NET-1 (RFC 5737): nothing answers, the message defers
${DEFER_DOMAIN}    defer.ns8-ci.test
${SMTP_USER}       ci-sender
${SMTP_PASS}       Ci,Sender,Pass,2026
${VAULT_TOKEN}     ci-dummy-vault-token-4242
${CHECK}           /root/kumomta_smtp_check.py

*** Keywords ***
Run action
    [Arguments]    ${action}    ${data}={}
    ${output}  ${rc} =    Execute Command    api-cli run module/${module_id}/${action} --data '${data}'
    ...    return_rc=True
    Should Be Equal As Integers    ${rc}  0    ${action} failed: ${output}
    ${result} =    Evaluate    json.loads('''${output}''')    modules=json
    RETURN    ${result}

Get configuration
    ${config} =    Run action    get-configuration
    RETURN    ${config}

Domain is queued
    [Arguments]    ${domain}
    ${status} =    Run action    get-queue-status
    Should Be True    ${status}[running]
    ${queued} =    Evaluate    [q['domain'] for q in $status['queues']] + [p['provider'] for p in $status['providers'] if p['queued'] or p['deferred']]
    Should Contain    ${queued}    ${domain}

State file
    [Arguments]    ${command}
    ${output}  ${rc} =    Execute Command    runagent -m ${module_id} ${command}
    ...    return_rc=True
    RETURN    ${output}    ${rc}

*** Test Cases ***
Check if kumomta is installed correctly
    ${output}  ${rc} =    Execute Command    add-module ${IMAGE_URL} 1
    ...    return_rc=True
    Should Be Equal As Integers    ${rc}  0
    &{output} =    Evaluate    ${output}
    Set Suite Variable    ${module_id}    ${output.module_id}
    Put File    ${CURDIR}/smtp_check.py    ${CHECK}

Check if kumomta can be configured
    ${rc} =    Execute Command
    ...    api-cli run module/${module_id}/configure-module --data '{"hostname":"${TEST_HOST}","lets_encrypt":false,"inbound_enabled":true,"inbound_port":25,"submission_enabled":true,"submission_port":587,"smtp_users":[{"username":"${SMTP_USER}","password":"${SMTP_PASS}"}],"domains":[{"domain":"${TEST_DOMAIN}","selector":"ci1"}],"inbound_routes":[{"domain":"${DEFER_DOMAIN}","host":"192.0.2.1","port":25}],"shaping":[{"domain":"gmail.com","connection_limit":3,"max_message_rate":"100/min"}],"retry_interval":"20m","max_age":"2d"}'
    ...    return_rc=True  return_stdout=False
    Should Be Equal As Integers    ${rc}  0
    ${output}  ${rc} =    Execute Command    runagent -m ${module_id} systemctl --user is-active kumomta.service
    ...    return_rc=True
    Should Be Equal    ${output}    active

Check if the configuration reads back without secrets
    ${output}  ${rc} =    Execute Command    api-cli run module/${module_id}/get-configuration --data '{}'
    ...    return_rc=True
    Should Be Equal As Integers    ${rc}  0
    Should Not Contain    ${output}    ${SMTP_PASS}
    Should Not Contain    ${output}    PRIVATE KEY
    ${config} =    Evaluate    json.loads('''${output}''')    modules=json
    Should Be Equal    ${config}[hostname]    ${TEST_HOST}
    Should Be Equal As Integers    ${config}[inbound_port]    25
    Should Be Equal    ${config}[smtp_users][0][username]    ${SMTP_USER}
    Dictionary Should Not Contain Key    ${config}[smtp_users][0]    password
    Should Be Equal    ${config}[inbound_routes][0][domain]    ${DEFER_DOMAIN}
    Should Be Equal    ${config}[shaping][0][domain]    gmail.com
    Should Not Be True    ${config}[vault_enabled]
    Should Not Be True    ${config}[vault_token_set]
    Should Be True    ${config}[cluster_relay_active]

Check if the secrets are private files
    ${output}  ${rc} =    State file    stat -c %a secrets secrets/smtp_users.toml secrets/api_password
    Should Be Equal As Integers    ${rc}  0
    Should Be Equal    ${output}    700\n600\n600
    ${output}  ${rc} =    State file    grep -rl ${SMTP_PASS} kumomta secrets settings.json environment
    Should Not Be Equal As Integers    ${rc}  0

Check if the listeners answer with an SMTP banner
    FOR    ${port}    IN    25    587
        ${output}  ${rc} =    Execute Command    python3 ${CHECK} banner 127.0.0.1 ${port}
        ...    return_rc=True
        Should Be Equal As Integers    ${rc}  0    ${output}
        Should Start With    ${output}    220 ${TEST_HOST}
    END

Check if the admin API needs authentication
    ${config} =    Get configuration
    ${output} =    Execute Command    curl -s -o /dev/null -w '\%{http_code}' http://127.0.0.1:${config}[api_port]/metrics.json
    Should Be Equal    ${output}    401

Check if an authenticated submission is accepted and queued
    ${output}  ${rc} =    Execute Command    python3 ${CHECK} submit 127.0.0.1 587 ${SMTP_USER} '${SMTP_PASS}' ci@${TEST_DOMAIN} user@${DEFER_DOMAIN}
    ...    return_rc=True
    Should Be Equal As Integers    ${rc}  0    ${output}
    Should Contain    ${output}    235
    Wait Until Keyword Succeeds    5 min    10 sec    Domain is queued    ${DEFER_DOMAIN}

Check if a wrong password is rejected
    ${output}  ${rc} =    Execute Command    python3 ${CHECK} badauth 127.0.0.1 587 ${SMTP_USER}
    ...    return_rc=True
    Should Be Equal As Integers    ${rc}  0    ${output}
    Should Contain    ${output}    535

Check if unauthenticated relaying is denied
    # The node address is neither loopback nor a trusted network
    ${address} =    Execute Command    ip -4 -o route get 192.0.2.1 | grep -o 'src [0-9.]*' | cut -d' ' -f2
    ${output}  ${rc} =    Execute Command    python3 ${CHECK} relay ${address} 25 someone@example.com someone@example.net
    ...    return_rc=True
    Should Be Equal As Integers    ${rc}  0    ${output}

Check if kumomta is offered as cluster smarthost
    ${output}  ${rc} =    Execute Command    api-cli run cluster/get-smarthost --data '{}'
    ...    return_rc=True
    Should Be Equal As Integers    ${rc}  0
    ${smarthost} =    Evaluate    json.loads('''${output}''')    modules=json
    ${ids} =    Evaluate    [m['mail_id'] for m in $smarthost['mail_server']]
    Should Contain    ${ids}    ${module_id}
    Should Not Contain    ${output}    ${SMTP_PASS}

Check if the DKIM key generation produces the TXT record
    ${config} =    Get configuration
    ${domain} =    Set Variable    ${config}[domains][0]
    Should Be Equal    ${domain}[key_location]    local
    Should Be Equal    ${domain}[dkim_record][name]    ci1._domainkey.${TEST_DOMAIN}
    Should Start With    ${domain}[dkim_record][value]    v=DKIM1; k=rsa; p=MII
    ${result} =    Run action    generate-dkim-key    {"domain":"${TEST_DOMAIN}","rotate":true}
    Should Start With    ${result}[dkim_record][value]    v=DKIM1; k=rsa; p=MII
    Should Not Be Equal    ${result}[dkim_record][value]    ${domain}[dkim_record][value]
    ${text} =    Evaluate    json.dumps($result)    modules=json
    Should Not Contain    ${text}    PRIVATE KEY

Check if OpenBao can be enabled
    ${rc} =    Execute Command
    ...    api-cli run module/${module_id}/configure-module --data '{"vault_enabled":true,"vault_address":"http://192.0.2.10:8200","vault_token":"${VAULT_TOKEN}","vault_mount":"secret","vault_path":"kumomta-ci","vault_key":"value"}'
    ...    return_rc=True  return_stdout=False
    Should Be Equal As Integers    ${rc}  0
    ${output}  ${rc} =    State file    stat -c %a openbao.env
    Should Be Equal    ${output}    600
    ${output}  ${rc} =    State file    grep -c 'vault_path = "kumomta-ci/smarthost"' kumomta/init.lua
    Should Be Equal    ${output}    1
    ${output}  ${rc} =    State file    grep -c 'vault_path_prefix" = "kumomta-ci/dkim"' kumomta/dkim_data.toml
    Should Be Equal    ${output}    1
    ${output}  ${rc} =    State file    grep -rl ${VAULT_TOKEN} kumomta settings.json environment
    Should Not Be Equal As Integers    ${rc}  0
    ${output}  ${rc} =    Execute Command    api-cli run module/${module_id}/get-configuration --data '{}'
    ...    return_rc=True
    Should Not Contain    ${output}    ${VAULT_TOKEN}
    ${config} =    Evaluate    json.loads('''${output}''')    modules=json
    Should Be True    ${config}[vault_enabled]
    Should Be True    ${config}[vault_token_set]
    ${output} =    Execute Command    runagent -m ${module_id} systemctl --user is-active kumomta.service
    Should Be Equal    ${output}    active
    ${output}  ${rc} =    Execute Command    python3 ${CHECK} banner 127.0.0.1 587
    ...    return_rc=True
    Should Be Equal As Integers    ${rc}  0    ${output}

Check if OpenBao can be disabled
    ${rc} =    Execute Command
    ...    api-cli run module/${module_id}/configure-module --data '{"vault_enabled":false}'
    ...    return_rc=True  return_stdout=False
    Should Be Equal As Integers    ${rc}  0
    ${output}  ${rc} =    State file    test -e openbao.env
    Should Not Be Equal As Integers    ${rc}  0
    ${output}  ${rc} =    State file    grep -c vault_path_prefix kumomta/dkim_data.toml
    Should Be Equal    ${output}    0
    ${config} =    Get configuration
    Should Not Be True    ${config}[vault_enabled]
    Should Be Equal    ${config}[domains][0][key_location]    local
    ${output} =    Execute Command    runagent -m ${module_id} systemctl --user is-active kumomta.service
    Should Be Equal    ${output}    active

Check if kumomta is removed correctly
    ${rc} =    Execute Command    remove-module --no-preserve ${module_id}
    ...    return_rc=True  return_stdout=False
    Should Be Equal As Integers    ${rc}  0
    Execute Command    rm -f ${CHECK}
