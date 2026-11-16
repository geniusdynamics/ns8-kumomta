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
${FAKE_BAO}        /root/kumomta_fake_openbao.py
${FAKE_BAO_PORT}   18200
${SMARTHOST_PASS}  Ci,Smarthost,Pass,2026

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

Configure
    [Arguments]    ${data}
    ${result} =    Run action    configure-module    ${data}
    RETURN    ${result}

Smarthost providers
    ${output}  ${rc} =    Execute Command    api-cli run cluster/get-smarthost --data '{}'
    ...    return_rc=True
    Should Be Equal As Integers    ${rc}  0
    ${smarthost} =    Evaluate    json.loads('''${output}''')    modules=json
    ${ids} =    Evaluate    [m['mail_id'] for m in $smarthost['mail_server']]
    RETURN    ${ids}

Submission key exists
    ${output}  ${rc} =    State file    python3 -c 'import agent, os; print(agent.redis_connect(use_replica=True).exists(os.environ["AGENT_ID"] + "/srv/tcp/submission"))'
    Should Be Equal As Integers    ${rc}  0    ${output}
    RETURN    ${output}

RCPT reply from the cluster address
    [Arguments]    ${address}
    ${output}  ${rc} =    Execute Command    python3 ${CHECK} rcpt ${address} 25 ci@${TEST_DOMAIN} someone@example.net ${address}
    ...    return_rc=True
    Should Be Equal As Integers    ${rc}  0    ${output}
    RETURN    ${output}

Event is logged
    [Arguments]    ${type}    ${recipient}
    ${result} =    Run action    list-recent-events    {"types":["${type}"],"limit":500}
    ${found} =    Evaluate    list(filter(lambda e, r=$recipient: e['recipient'] == r, $result['events']))
    Should Not Be Empty    ${found}    no ${type} record for ${recipient} yet
    RETURN    ${found}[0]

Submit
    [Arguments]    ${recipient}
    ${output}  ${rc} =    Execute Command    python3 ${CHECK} submit 127.0.0.1 587 ${SMTP_USER} '${SMTP_PASS}' ci@${TEST_DOMAIN} ${recipient}
    ...    return_rc=True
    Should Be Equal As Integers    ${rc}  0    ${output}

Fake OpenBao answers
    ${output} =    Execute Command    curl -s -o /dev/null -w '\%{http_code}' -H 'X-Vault-Token: wrong' http://127.0.0.1:${FAKE_BAO_PORT}/v1/secret/data/x
    Should Be Equal    ${output}    403

Warning ids
    [Arguments]    ${result}
    ${ids} =    Evaluate    [w['id'] for w in $result['warnings']]
    RETURN    ${ids}

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

Check if the cluster relay trusts the cluster address
    ${config} =    Get configuration
    Should Be True    ${config}[cluster_relay]
    Should Be True    ${config}[cluster_relay_active]
    Should Be Empty    ${config}[warnings]
    ${output} =    Submission key exists
    Should Be Equal    ${output}    1
    Skip If    '${config}[node_address]' == ''    no cluster VPN address on this node
    ${output} =    RCPT reply from the cluster address    ${config}[node_address]
    Should Start With    ${output}    250

Check if the cluster relay can be turned off
    ${config} =    Get configuration
    ${result} =    Configure    {"cluster_relay":false}
    ${after} =    Get configuration
    Should Not Be True    ${after}[cluster_relay]
    Should Not Be True    ${after}[cluster_relay_active]
    ${ids} =    Smarthost providers
    Should Not Contain    ${ids}    ${module_id}
    ${output} =    Submission key exists
    Should Be Equal    ${output}    0
    ${output}  ${rc} =    State file    grep -c -F '${config}[cluster_network]' kumomta/relay_hosts.toml
    Should Be Equal    ${output}    0
    Skip If    '${config}[node_address]' == ''    no cluster VPN address on this node
    ${output} =    RCPT reply from the cluster address    ${config}[node_address]
    Should Not Start With    ${output}    250

Check if the cluster relay can be turned back on
    ${result} =    Configure    {"cluster_relay":true}
    ${ids} =    Smarthost providers
    Should Contain    ${ids}    ${module_id}
    ${output} =    Submission key exists
    Should Be Equal    ${output}    1

Check if sink mode records the messages as delivered
    ${result} =    Configure    {"sink_enabled":true}
    ${ids} =    Warning ids    ${result}
    Should Contain    ${ids}    sink_mode_enabled
    ${config} =    Get configuration
    Should Be True    ${config}[sink_enabled]
    ${ids} =    Warning ids    ${config}
    Should Contain    ${ids}    sink_mode_enabled
    Submit    sink-ok@example.net
    Submit    tempfail@example.net
    Submit    permfail@example.net
    ${event} =    Wait Until Keyword Succeeds    5 min    15 sec    Event is logged    Delivery    sink-ok@example.net
    Should Contain    ${event}[response]    sink
    Wait Until Keyword Succeeds    3 min    15 sec    Event is logged    TransientFailure    tempfail@example.net
    Wait Until Keyword Succeeds    3 min    15 sec    Event is logged    Bounce    permfail@example.net

Check if sink mode can be turned off
    ${result} =    Configure    {"sink_enabled":false}
    ${ids} =    Warning ids    ${result}
    Should Not Contain    ${ids}    sink_mode_enabled
    ${config} =    Get configuration
    Should Not Be True    ${config}[sink_enabled]
    Should Be Empty    ${config}[warnings]
    ${output}  ${rc} =    State file    grep -A1 sink kumomta/queues.toml
    Should Contain    ${output}    "enabled" = false

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

Check if the OpenBao-only secrets are listed
    Put File    ${CURDIR}/fake_openbao.py    ${FAKE_BAO}
    Execute Command    systemd-run --unit=kumomta-ci-openbao python3 ${FAKE_BAO} ${FAKE_BAO_PORT} ${VAULT_TOKEN}
    Wait Until Keyword Succeeds    30 sec    2 sec    Fake OpenBao answers
    ${result} =    Configure    {"vault_enabled":true,"vault_address":"http://127.0.0.1:${FAKE_BAO_PORT}","vault_token":"${VAULT_TOKEN}","vault_mount":"secret","vault_path":"kumomta-ci","vault_key":"value","smarthost_password":"${SMARTHOST_PASS}"}
    ${result} =    Run action    generate-dkim-key    {"domain":"${TEST_DOMAIN}"}
    Should Be Equal    ${result}[key_location]    openbao
    ${output}  ${rc} =    State file    test -e dkim/${TEST_DOMAIN}/ci1.key
    Should Not Be Equal As Integers    ${rc}  0
    ${output}  ${rc} =    State file    test -e secrets/smarthost_password
    Should Not Be Equal As Integers    ${rc}  0
    ${output}  ${rc} =    Execute Command    api-cli run module/${module_id}/list-openbao-only-secrets --data '{}'
    ...    return_rc=True
    Should Be Equal As Integers    ${rc}  0
    Should Not Contain    ${output}    PRIVATE KEY
    Should Not Contain    ${output}    ${SMARTHOST_PASS}
    Should Not Contain    ${output}    ${VAULT_TOKEN}
    ${listing} =    Evaluate    json.loads('''${output}''')    modules=json
    ${names} =    Evaluate    sorted(i['name'] for i in $listing['items'])
    ${expected} =    Evaluate    sorted(['ci1._domainkey.${TEST_DOMAIN}', 'smarthost_password'])
    Should Be Equal    ${names}    ${expected}
    Should Be True    ${listing}[copyable]
    ${output} =    Execute Command    runagent -m ${module_id} systemctl --user is-active kumomta.service
    Should Be Equal    ${output}    active

Check if turning OpenBao off warns about the OpenBao-only secrets
    ${result} =    Configure    {"vault_enabled":false}
    ${ids} =    Warning ids    ${result}
    Should Contain    ${ids}    openbao_items_unavailable
    ${items} =    Evaluate    [w['items'] for w in $result['warnings'] if w['id'] == 'openbao_items_unavailable'][0]
    Should Contain    ${items}    ci1._domainkey.${TEST_DOMAIN}
    ${config} =    Get configuration
    Should Be Equal    ${config}[domains][0][key_location]    missing
    Should Not Be True    ${config}[smarthost_password_set]

Check if the OpenBao-only secrets can be copied back to local
    ${result} =    Configure    {"vault_enabled":true,"vault_token":"${VAULT_TOKEN}","smarthost_password":"${SMARTHOST_PASS}"}
    ${config} =    Get configuration
    Should Be Equal    ${config}[domains][0][key_location]    openbao
    ${result} =    Run action    copy-openbao-to-local
    ${copied} =    Evaluate    sorted($result['copied'])
    ${expected} =    Evaluate    sorted(['ci1._domainkey.${TEST_DOMAIN}', 'smarthost_password'])
    Should Be Equal    ${copied}    ${expected}
    Should Be Empty    ${result}[failed]
    ${output}  ${rc} =    State file    stat -c %a dkim/${TEST_DOMAIN}/ci1.key secrets/smarthost_password
    Should Be Equal    ${output}    600\n600
    ${listing} =    Run action    list-openbao-only-secrets
    Should Be Empty    ${listing}[items]
    ${result} =    Configure    {"vault_enabled":false}
    ${ids} =    Warning ids    ${result}
    Should Not Contain    ${ids}    openbao_items_unavailable
    ${config} =    Get configuration
    Should Not Be True    ${config}[vault_enabled]
    Should Be Equal    ${config}[domains][0][key_location]    local
    Should Be True    ${config}[smarthost_password_set]
    ${output} =    Execute Command    runagent -m ${module_id} systemctl --user is-active kumomta.service
    Should Be Equal    ${output}    active
    [Teardown]    Execute Command    systemctl stop kumomta-ci-openbao

Check if kumomta is removed correctly
    ${rc} =    Execute Command    remove-module --no-preserve ${module_id}
    ...    return_rc=True  return_stdout=False
    Should Be Equal As Integers    ${rc}  0
    Execute Command    rm -f ${CHECK} ${FAKE_BAO}
