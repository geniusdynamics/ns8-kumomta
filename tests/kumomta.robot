*** Settings ***
Library    SSHLibrary
Library    Collections

*** Variables ***
${SCENARIO}        install
${RELEASE_IMAGE}   ghcr.io/geniusdynamics/kumomta:1.0.0
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
${API_HOST}        mta-api.ns8-ci.test
${API_DOMAIN}      customer1.ns8-ci.test
${INT_USER}        ci-platform
${INT_PASS}        CiPlatformPass2026xyz
${FAKE_HOOK}       /root/kumomta_fake_webhook.py
${HOOK_FILE}       /root/kumomta_webhook.jsonl
${HOOK_PORT}       18300
${HOOK_TOKEN}      ci-webhook-bearer-token
${HOOK_SECRET}     ci-webhook-signing-secret-2026
${METRICS_HOST}    mta-metrics.ns8-ci.test
${METRICS_PASS}    CiMetricsPass2026

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

API call
    [Arguments]    ${method}    ${path}    ${user}    ${password}    ${body}={}
    ${output}  ${rc} =    Execute Command    curl -sk --max-time 60 --resolve ${API_HOST}:443:127.0.0.1 -u '${user}:${password}' -X ${method} -H 'Content-Type: application/json' -d '${body}' -w '\\n\%{http_code}' https://${API_HOST}${path}
    ...    return_rc=True
    Should Be Equal As Integers    ${rc}  0    ${output}
    ${reply}  ${code} =    Evaluate    $output.rsplit('\\n', 1)
    RETURN    ${code}    ${reply}

API answers
    ${code}  ${reply} =    API call    GET    /api/v1/whoami    ${INT_USER}    ${INT_PASS}
    Should Be Equal    ${code}    200    ${reply}
    ${who} =    Evaluate    json.loads($reply)    modules=json
    RETURN    ${who}

Inject
    [Arguments]    ${recipient}
    ${body} =    Set Variable    {"envelope_sender":"noreply@${API_DOMAIN}","content":{"from":{"email":"noreply@${API_DOMAIN}","name":"CI"},"subject":"ns8-kumomta CI injection","text_body":"Injected by the CI","headers":{"X-Campaign":"ci-campaign"}},"recipients":[{"email":"${recipient}","metadata":{"ref":"ci-ref-1"}}]}
    ${code}  ${reply} =    API call    POST    /api/inject/v1    ${INT_USER}    ${INT_PASS}    ${body}
    Should Be Equal    ${code}    200    ${reply}
    ${result} =    Evaluate    json.loads($reply)    modules=json
    RETURN    ${result}

Inject with tenant
    [Arguments]    ${recipient}    ${tenant}    ${domain}=${API_DOMAIN}
    ${body} =    Set Variable    {"envelope_sender":"noreply@${domain}","content":{"from":{"email":"noreply@${domain}","name":"CI"},"subject":"ns8-kumomta CI tenant","text_body":"Injected by the CI","headers":{"X-Tenant":"${tenant}","X-Campaign":"ci-campaign"}},"recipients":[{"email":"${recipient}"}]}
    ${code}  ${reply} =    API call    POST    /api/inject/v1    ${INT_USER}    ${INT_PASS}    ${body}
    Should Be Equal    ${code}    200    ${reply}
    ${result} =    Evaluate    json.loads($reply)    modules=json
    RETURN    ${result}

Loopback relay is refused
    ${output}  ${rc} =    Execute Command    python3 ${CHECK} rcpt 127.0.0.1 25 someone@example.com loopback@example.net
    ...    return_rc=True
    Should Not Start With    ${output}    250
    RETURN    ${output}

Webhook record is valid
    [Arguments]    ${recipient}
    ${output}  ${rc} =    Execute Command    python3 ${FAKE_HOOK} check ${HOOK_FILE} ${recipient} ${HOOK_SECRET} ${HOOK_TOKEN}
    ...    return_rc=True
    Should Be Equal As Integers    ${rc}  0    ${output}
    RETURN    ${output}

Metrics answer
    [Arguments]    ${credentials}    ${expected}
    ${auth} =    Set Variable If    '${credentials}' != ''    -u '${credentials}'    ${EMPTY}
    ${output}  ${rc} =    Execute Command    curl -sk -D - -o /dev/null --max-time 30 --resolve ${METRICS_HOST}:443:127.0.0.1 ${auth} https://${METRICS_HOST}/metrics
    ...    return_rc=True
    Should Be Equal As Integers    ${rc}  0    ${output}
    ${output} =    Evaluate    $output.lower()
    Should Match Regexp    ${output}    ^http/\\S+ ${expected}
    RETURN    ${output}

State file
    [Arguments]    ${command}
    ${output}  ${rc} =    Execute Command    runagent -m ${module_id} ${command}
    ...    return_rc=True
    RETURN    ${output}    ${rc}

*** Test Cases ***
Check if kumomta is installed correctly
    ${initial_image} =    Set Variable If    $SCENARIO == 'update'    ${RELEASE_IMAGE}    ${IMAGE_URL}
    ${output}  ${rc} =    Execute Command    add-module ${initial_image} 1
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

Check if a populated standalone instance survives the update
    Skip If    $SCENARIO != 'update'    Fresh installation
    ${before} =    Get configuration
    ${hashes_before}  ${rc} =    State file    sha256sum secrets/smtp_users.toml dkim/${TEST_DOMAIN}/ci1.key
    Should Be Equal As Integers    ${rc}  0    ${hashes_before}
    Submit    before-update@${DEFER_DOMAIN}
    Wait Until Keyword Succeeds    2 min    5 sec    Domain is queued    ${DEFER_DOMAIN}
    ${output}  ${rc} =    Execute Command
    ...    api-cli run update-module --data '{"force":true,"module_url":"${IMAGE_URL}","instances":["${module_id}"]}'
    ...    return_rc=True
    Should Be Equal As Integers    ${rc}  0    ${output}
    ${image}  ${rc} =    State file    printenv IMAGE_URL
    Should Be Equal As Integers    ${rc}  0
    Should Be Equal    ${image}    ${IMAGE_URL}
    Wait Until Keyword Succeeds    2 min    5 sec    Domain is queued    ${DEFER_DOMAIN}
    ${after} =    Get configuration
    FOR    ${field}    IN    hostname    smtp_users    domains    inbound_routes    shaping    retry_interval    max_age
        Should Be Equal    ${after}[${field}]    ${before}[${field}]
    END
    Should Be Equal    ${after}[cluster_store]    none
    Should Be Equal    ${after}[cluster_status][mode]    standalone
    Should Not Be True    ${after}[tsa_enabled]
    ${hashes_after}  ${rc} =    State file    sha256sum secrets/smtp_users.toml dkim/${TEST_DOMAIN}/ci1.key
    Should Be Equal As Integers    ${rc}  0    ${hashes_after}
    Should Be Equal    ${hashes_after}    ${hashes_before}

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

Check if the metrics route asks for the metrics user
    ${result} =    Configure    {"metrics_host":"${METRICS_HOST}","metrics_password":"${METRICS_PASS}","metrics_public":false}
    ${config} =    Get configuration
    Should Not Be True    ${config}[metrics_public]
    ${output} =    Wait Until Keyword Succeeds    1 min    5 sec    Metrics answer    ${EMPTY}    401
    Should Contain    ${output}    www-authenticate: basic realm=
    Wait Until Keyword Succeeds    1 min    5 sec    Metrics answer    metrics:${METRICS_PASS}    200
    ${result} =    Configure    {"metrics_public":true}
    Wait Until Keyword Succeeds    1 min    5 sec    Metrics answer    metrics:${METRICS_PASS}    200
    [Teardown]    Configure    {"metrics_host":""}

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

Check if the loopback trust can be turned off and on
    ${output}  ${rc} =    Execute Command    python3 ${CHECK} rcpt 127.0.0.1 25 someone@example.com loopback@example.net
    ...    return_rc=True
    Should Start With    ${output}    250
    ${result} =    Configure    {"trust_loopback":false}
    ${config} =    Get configuration
    Should Not Be True    ${config}[trust_loopback]
    ${output}  ${rc} =    State file    grep -c -F '127.0.0.0/8' kumomta/relay_hosts.toml
    Should Be Equal    ${output}    0
    ${output} =    Wait Until Keyword Succeeds    1 min    5 sec    Loopback relay is refused
    ${result} =    Configure    {"trust_loopback":true}
    ${output}  ${rc} =    State file    grep -c -F '127.0.0.0/8' kumomta/relay_hosts.toml
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

Check if an integration credential can be configured
    ${result} =    Configure    {"integrations":[{"name":"${INT_USER}","password":"${INT_PASS}","tenant":"ci-tenant","scopes":["inject","domains"],"max_message_rate":"1000/min"}],"api_host":"${API_HOST}"}
    ${output}  ${rc} =    Execute Command    api-cli run module/${module_id}/get-configuration --data '{}'
    ...    return_rc=True
    Should Not Contain    ${output}    ${INT_PASS}
    ${config} =    Evaluate    json.loads('''${output}''')    modules=json
    Should Be Equal    ${config}[integrations][0][name]    ${INT_USER}
    Should Be True    ${config}[integrations][0][password_set]
    Should Be Equal    ${config}[api_endpoints][inject]    https://${API_HOST}/api/inject/v1
    ${output}  ${rc} =    State file    stat -c %a secrets/integrations.toml secrets/integrations.json
    Should Be Equal    ${output}    600\n600
    ${output}  ${rc} =    State file    grep -rl ${INT_PASS} kumomta secrets settings.json environment
    Should Not Be Equal As Integers    ${rc}  0
    ${output} =    Execute Command    runagent -m ${module_id} systemctl --user is-active kumomta-api.service
    Should Be Equal    ${output}    active
    ${who} =    Wait Until Keyword Succeeds    1 min    5 sec    API answers
    Should Be Equal    ${who}[tenant]    ci-tenant

Check if a wrong integration credential is rejected
    ${code}  ${reply} =    API call    GET    /api/v1/domains    ${INT_USER}    wrong-password-123456
    Should Be Equal    ${code}    401
    ${code}  ${reply} =    API call    POST    /api/inject/v1    ${INT_USER}    wrong-password-123456    {"envelope_sender":"a@${API_DOMAIN}","content":"Subject: x\\r\\n\\r\\nx","recipients":[{"email":"x@example.net"}]}
    Should Be Equal    ${code}    401
    ${code}  ${reply} =    API call    GET    /api/v1/domains    nobody    ${INT_PASS}
    Should Be Equal    ${code}    401
    # The admin API of kumod is not routed, even with valid credentials
    ${code}  ${reply} =    API call    POST    /api/admin/bump-config-epoch    ${INT_USER}    ${INT_PASS}
    Should Be Equal    ${code}    404

Check if a sending domain can be added through the API
    ${code}  ${reply} =    API call    POST    /api/v1/domains    ${INT_USER}    ${INT_PASS}    {"domain":"${API_DOMAIN}","selector":"ci2"}
    Should Be Equal    ${code}    201    ${reply}
    Should Not Contain    ${reply}    PRIVATE KEY
    ${dom} =    Evaluate    json.loads($reply)    modules=json
    Should Be Equal    ${dom}[status]    pending
    Should Be Equal    ${dom}[owner]    ${INT_USER}
    Should Be Equal    ${dom}[tenant]    ci-tenant
    ${records} =    Evaluate    {r['check']: r for r in $dom['records']}
    Should Be Equal    ${records}[dkim][name]    ci2._domainkey.${API_DOMAIN}
    Should Start With    ${records}[dkim][value]    v=DKIM1; k=rsa; p=MII
    Should Be Equal    ${records}[spf][value]    v=spf1 a:${TEST_HOST} ~all
    Should Be Equal    ${records}[dmarc][name]    _dmarc.${API_DOMAIN}
    ${code}  ${reply} =    API call    POST    /api/v1/domains    ${INT_USER}    ${INT_PASS}    {"domain":"${API_DOMAIN}"}
    Should Be Equal    ${code}    409
    ${listing} =    Run action    list-domains
    ${owners} =    Evaluate    {d['domain']: d['owner'] for d in $listing['domains']}
    Should Be Equal    ${owners}[${API_DOMAIN}]    ${INT_USER}
    Should Be Equal    ${owners}[${TEST_DOMAIN}]    ${EMPTY}

Check if the domain validation is pending without public DNS
    ${code}  ${reply} =    API call    POST    /api/v1/domains/${API_DOMAIN}/validate    ${INT_USER}    ${INT_PASS}
    Should Be Equal    ${code}    200    ${reply}
    ${dom} =    Evaluate    json.loads($reply)    modules=json
    Should Be Equal    ${dom}[status]    pending
    Should Not Be Empty    ${dom}[last_checked]
    ${checks} =    Evaluate    {c['name']: c['status'] for c in $dom['checks']}
    Should Be Equal    ${checks}[dkim]    missing
    ${result} =    Run action    validate-domain    {"domain":"${TEST_DOMAIN}"}
    Should Be Equal    ${result}[domains][0][status]    pending
    ${code}  ${reply} =    API call    GET    /api/v1/domains/${TEST_DOMAIN}    ${INT_USER}    ${INT_PASS}
    Should Be Equal    ${code}    404

Check if an unverified domain cannot send
    ${result} =    Inject    inject-unverified@example.net
    Should Be Equal As Integers    ${result}[fail_count]    1
    ${errors} =    Evaluate    ' '.join($result['errors'])
    Should Contain    ${errors}    not verified

Check if the integration injects over HTTPS without the admin user
    ${result} =    Configure    {"require_verified_domains":false}
    ${result} =    Inject    inject-ok@example.net
    Should Be Equal As Integers    ${result}[success_count]    1    ${result}
    Should Be Equal As Integers    ${result}[fail_count]    0
    ${event} =    Wait Until Keyword Succeeds    5 min    15 sec    Event is logged    Delivery    inject-ok@example.net
    Should Be Equal    ${event}[queue]    ci-campaign:ci-tenant@example.net
    Should Be Equal    ${event}[sender]    noreply@${API_DOMAIN}
    ${result} =    Configure    {"require_verified_domains":true}

Check if the webhook posts signed events with the tenant and metadata
    Put File    ${CURDIR}/fake_webhook.py    ${FAKE_HOOK}
    Execute Command    rm -f ${HOOK_FILE}
    Execute Command    systemd-run --unit=kumomta-ci-webhook python3 ${FAKE_HOOK} serve ${HOOK_PORT} ${HOOK_FILE}
    ${result} =    Configure    {"webhook_enabled":true,"webhook_url":"http://127.0.0.1:${HOOK_PORT}/hook","webhook_token":"${HOOK_TOKEN}","webhook_signing_secret":"${HOOK_SECRET}","webhook_record_types":["Delivery","Bounce","TransientFailure"],"require_verified_domains":false}
    ${output}  ${rc} =    State file    grep -rl ${HOOK_SECRET} kumomta settings.json environment
    Should Not Be Equal As Integers    ${rc}  0
    ${config} =    Get configuration
    Should Be True    ${config}[webhook_signing_secret_set]
    ${result} =    Inject    hook-ok@example.net
    Should Be Equal As Integers    ${result}[success_count]    1    ${result}
    ${output} =    Wait Until Keyword Succeeds    3 min    10 sec    Webhook record is valid    hook-ok@example.net
    ${record} =    Evaluate    json.loads($output)    modules=json
    Should Be Equal    ${record}[type]    Delivery
    Should Be Equal    ${record}[meta][tenant]    ci-tenant
    Should Be Equal    ${record}[meta][campaign]    ci-campaign
    Should Be Equal    ${record}[meta][extra][ref]    ci-ref-1
    [Teardown]    Run Keywords    Execute Command    systemctl stop kumomta-ci-webhook
    ...    AND    Configure    {"webhook_enabled":false,"require_verified_domains":true}

Check if a sending domain can be removed through the API
    ${code}  ${reply} =    API call    DELETE    /api/v1/domains/${API_DOMAIN}    ${INT_USER}    ${INT_PASS}
    Should Be Equal    ${code}    200    ${reply}
    ${output}  ${rc} =    State file    test -e dkim/${API_DOMAIN}/ci2.key
    Should Not Be Equal As Integers    ${rc}  0
    ${listing} =    Run action    list-domains
    ${names} =    Evaluate    [d['domain'] for d in $listing['domains']]
    Should Not Contain    ${names}    ${API_DOMAIN}

Check if a multi-tenant credential takes the tenant from X-Tenant
    ${result} =    Configure    {"integrations":[{"name":"${INT_USER}","tenant":"","tenant_prefix":"ci-","scopes":["inject","domains"],"max_message_rate":"1000/min","max_domains":1}],"require_verified_domains":false}
    ${who} =    Wait Until Keyword Succeeds    1 min    5 sec    API answers
    Should Be Equal    ${who}[tenant]    ${EMPTY}
    Should Be Equal    ${who}[tenant_prefix]    ci-
    ${code}  ${reply} =    API call    POST    /api/v1/domains    ${INT_USER}    ${INT_PASS}    {"domain":"${API_DOMAIN}","selector":"ci3","tenant":"other-cust"}
    Should Be Equal    ${code}    422    ${reply}
    ${code}  ${reply} =    API call    POST    /api/v1/domains    ${INT_USER}    ${INT_PASS}    {"domain":"${API_DOMAIN}","selector":"ci3","tenant":"ci-cust1"}
    Should Be Equal    ${code}    201    ${reply}
    ${dom} =    Evaluate    json.loads($reply)    modules=json
    Should Be Equal    ${dom}[tenant]    ci-cust1
    ${code}  ${reply} =    API call    POST    /api/v1/domains    ${INT_USER}    ${INT_PASS}    {"domain":"second.${API_DOMAIN}","selector":"ci3"}
    Should Be Equal    ${code}    403    ${reply}
    Should Contain    ${reply}    domain_quota
    ${config} =    Get configuration
    Should Be Equal As Integers    ${config}[integrations][0][domains_count]    1
    ${result} =    Inject with tenant    tenant-ok@example.net    ci-cust2
    Should Be Equal As Integers    ${result}[success_count]    1    ${result}
    ${event} =    Wait Until Keyword Succeeds    5 min    15 sec    Event is logged    Delivery    tenant-ok@example.net
    Should Be Equal    ${event}[queue]    ci-campaign:ci-cust2@example.net
    ${result} =    Inject with tenant    tenant-denied@example.net    other-cust
    Should Be Equal As Integers    ${result}[fail_count]    1    ${result}
    ${errors} =    Evaluate    ' '.join($result['errors'])
    Should Contain    ${errors}    not allowed
    [Teardown]    Run Keywords    API call    DELETE    /api/v1/domains/${API_DOMAIN}    ${INT_USER}    ${INT_PASS}
    ...    AND    Configure    {"integrations":[{"name":"${INT_USER}","tenant":"ci-tenant","scopes":["inject","domains"],"max_message_rate":"1000/min"}],"require_verified_domains":true}

Guarded submission shares a recipient cap and handles scanner decisions
    Put File    ${CURDIR}/fake_rspamd.py    /root/kumomta_fake_rspamd.py
    Execute Command    systemd-run --unit=kumomta-ci-rspamd python3 /root/kumomta_fake_rspamd.py 18312
    Configure    {"sink_enabled":true,"require_verified_domains":false,"integrations":[{"name":"${INT_USER}","tenant":"","tenant_prefix":"ci-","scopes":["inject","smtp","domains"]}],"guarded_integrations":["${INT_USER}"],"tenant_policies":{"ci-cap":{"admission_per_hour":2},"ci-hold":{"admission_per_hour":20,"paused":true},"ci-scan":{"admission_per_hour":20}},"rspamd_url":"http://127.0.0.1:18312/checkv2","rspamd_password":"ci-only-rspamd-password"}
    ${config} =    Get configuration
    Should Be True    ${config}[rspamd_password_set]
    Dictionary Should Not Contain Key    ${config}    rspamd_password
    ${result} =    Inject with tenant    guard-unknown@example.net    ci-missing    ${TEST_DOMAIN}
    Should Be Equal As Integers    ${result}[fail_count]    1
    Should Contain    ${result}[errors][0]    configured tenant policy
    ${result} =    Inject with tenant    guard-paused@example.net    ci-hold    ${TEST_DOMAIN}
    Should Be Equal As Integers    ${result}[fail_count]    1
    Should Contain    ${result}[errors][0]    tenant sending is paused
    ${output}    ${rc} =    Execute Command
    ...    python3 ${CHECK} submit 127.0.0.1 587 ${INT_USER} '${INT_PASS}' ci@${TEST_DOMAIN} guard-smtp@example.net ci-cap
    ...    return_rc=True
    Should Be Equal As Integers    ${rc}    0    ${output}
    ${result} =    Inject with tenant    guard-http@example.net    ci-cap    ${TEST_DOMAIN}
    Should Be Equal As Integers    ${result}[success_count]    1
    ${result} =    Inject with tenant    guard-exhausted@example.net    ci-cap    ${TEST_DOMAIN}
    Should Be Equal As Integers    ${result}[fail_count]    1
    Should Contain    ${result}[errors][0]    tenant admission limit reached
    ${result} =    Inject with tenant    guard-scan-reject@example.net    ci-scan    ${TEST_DOMAIN}
    Should Be Equal As Integers    ${result}[fail_count]    1
    Should Contain    ${result}[errors][0]    rejected by outbound content policy
    Execute Command    systemctl stop kumomta-ci-rspamd
    ${result} =    Inject with tenant    guard-scanner-down@example.net    ci-scan    ${TEST_DOMAIN}
    Should Be Equal As Integers    ${result}[fail_count]    1
    Should Contain    ${result}[errors][0]    outbound content check deferred
    [Teardown]    Run Keywords    Execute Command    systemctl stop kumomta-ci-rspamd
    ...    AND    Configure    {"tenant_policies":{},"guarded_integrations":[],"rspamd_url":"","rspamd_password_clear":true,"integrations":[{"name":"${INT_USER}","tenant":"ci-tenant","scopes":["inject","domains"],"max_message_rate":"1000/min"}],"require_verified_domains":true}

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

Check if the OpenBao client status needs no provider
    ${status} =    Run action    get-openbao-client-status
    Should Be Equal    ${status}[status]    none
    Should Not Be True    ${status}[client][active]
    ${output}  ${rc} =    Execute Command    api-cli run module/${module_id}/request-openbao-access --data '{}'
    ...    return_rc=True
    Should Not Be Equal As Integers    ${rc}  0
    Should Contain    ${output}    required

Check if provisioned mode works against a fake ns8-openbao
    Execute Command    mkdir -p /tmp/kumo-obc && chmod 755 /tmp/kumo-obc
    Put File    ${CURDIR}/fake_bao_api.py    /tmp/kumo-obc/fake_bao_api.py    mode=0644
    Put File    ${CURDIR}/openbao_client_flow.py    /tmp/kumo-obc/openbao_client_flow.py    mode=0644
    ${out}  ${err}  ${rc} =    Execute Command    runagent -m ${module_id} python3 /tmp/kumo-obc/openbao_client_flow.py
    ...    return_rc=True    return_stderr=True
    Should Be Equal As Integers    ${rc}    0    ${err}
    ${r} =    Evaluate    json.loads($out)    modules=json
    Should Be Equal    ${r}[first]    pending
    Should Be Equal    ${r}[approved]    provisioned
    Should Be Equal    ${r}[source]    provisioned
    Should Be Equal    ${r}[path]    modules/${module_id}
    Should Be True    ${r}[token_hidden]
    Should Be Equal    ${r}[dir_mode]    0o700
    Should Be Equal    ${r}[revoked]    dropped
    Should Be True    ${r}[fallback_local]
    [Teardown]    Execute Command    rm -rf /tmp/kumo-obc

Check if kumomta is removed correctly
    ${rc} =    Execute Command    remove-module --no-preserve ${module_id}
    ...    return_rc=True  return_stdout=False
    Should Be Equal As Integers    ${rc}  0
    Execute Command    rm -f ${CHECK} ${FAKE_BAO} ${FAKE_HOOK} ${HOOK_FILE}
