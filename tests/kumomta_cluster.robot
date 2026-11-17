*** Settings ***
Documentation     Multi-node cluster on a single test node: two instances share a
...               throwaway Valkey (a manual store bound to the cluster VPN
...               address) and run tsa-daemon; the second one joins the first
...               with cluster_join. Then the store stops: the instances fall back
...               to local throttles with a warning and keep accepting mail.
...               The store user has the ACL of ns8-valkey clients
...               (+@all -@admin -@dangerous). Last, an instance uses a real
...               ns8-valkey (one-member Valkey Cluster) through grant-client.
Library           SSHLibrary
Library           Collections

*** Variables ***
${HOST_A}          mx-a.ns8-ci.test
${HOST_B}          mx-b.ns8-ci.test
${CI_DOMAIN}       ns8-ci.test
${VALKEY_IMAGE}    docker.io/valkey/valkey:9.0.7-alpine
${VALKEY_PORT}     16379
# Test fixtures only: the throwaway store of this suite. kumomta logs in
# as ${ACL_USER}, with the permissions ns8-valkey gives its clients
${STORE_PASS}      CiClusterStorePass2026
${ACL_USER}        ci-kumo
${ACL_PASS}        CiClusterAclPass2026
${NS8_VALKEY}      ghcr.io/geniusdynamics/valkey:latest
${VALKEY_ID}       ${EMPTY}
${CHECK}           /root/kumomta_smtp_check.py

*** Keywords ***
Run on
    [Arguments]    ${module}    ${action}    ${data}={}
    ${output}  ${rc} =    Execute Command    api-cli run module/${module}/${action} --data '${data}'
    ...    return_rc=True
    Should Be Equal As Integers    ${rc}  0    ${action} on ${module} failed: ${output}
    Should Not Contain    ${output}    ${STORE_PASS}
    Should Not Contain    ${output}    ${ACL_PASS}
    ${result} =    Evaluate    json.loads('''${output}''')    modules=json
    RETURN    ${result}

Configuration of
    [Arguments]    ${module}
    ${config} =    Run on    ${module}    get-configuration
    RETURN    ${config}

Mode is
    [Arguments]    ${module}    ${mode}
    ${config} =    Configuration of    ${module}
    Should Be Equal    ${config}[cluster_status][mode]    ${mode}    ${config}[cluster_status]
    RETURN    ${config}

In module
    [Arguments]    ${module}    ${command}
    ${output}  ${rc} =    Execute Command    runagent -m ${module} ${command}
    ...    return_rc=True
    RETURN    ${output}    ${rc}

Unit is active
    [Arguments]    ${module}    ${unit}
    ${output}  ${rc} =    In module    ${module}    systemctl --user is-active ${unit}
    Should Be Equal    ${output}    active

Check twice
    [Arguments]    ${module}
    In module    ${module}    kumomta-cluster-check
    In module    ${module}    kumomta-cluster-check

Check and expect
    [Arguments]    ${module}    ${mode}
    In module    ${module}    kumomta-cluster-check
    ${config} =    Mode is    ${module}    ${mode}
    RETURN    ${config}

Peer daemon is listed
    [Arguments]    ${module}    ${count}
    ${config} =    Configuration of    ${module}
    Length Should Be    ${config}[cluster_status][tsa_peers]    ${count}

Start the throwaway store
    ${output}  ${rc} =    Execute Command
    ...    podman run -d --rm --name kumomta-ci-valkey --network host ${VALKEY_IMAGE} valkey-server --bind ${VPN_ADDR} --port ${VALKEY_PORT} --requirepass ${STORE_PASS} --save '' --user ${ACL_USER} on '>${ACL_PASS}' '~*' '&*' '+@all' '-@admin' '-@dangerous'
    ...    return_rc=True
    Should Be Equal As Integers    ${rc}  0    ${output}

Valkey record is published
    [Arguments]    ${module}
    ${output}  ${rc} =    In module    ${module}    python3 -c 'import agent; print(agent.redis_connect(use_replica=True).hget("module/${VALKEY_ID}/srv/tcp/valkey", "host") or "")'
    Should Not Be Empty    ${output}    no valkey record yet

Store has throttle keys
    ${output} =    Execute Command    podman exec kumomta-ci-valkey valkey-cli -h ${VPN_ADDR} -p ${VALKEY_PORT} --no-auth-warning -a ${STORE_PASS} DBSIZE
    Should Be True    int('${output}'.strip() or 0) > 0    no key in the store yet

*** Test Cases ***
Install two instances and a throwaway store
    ${output}  ${rc} =    Execute Command    add-module ${IMAGE_URL} 1
    ...    return_rc=True
    Should Be Equal As Integers    ${rc}  0
    &{a} =    Evaluate    ${output}
    Set Suite Variable    ${A}    ${a.module_id}
    ${output}  ${rc} =    Execute Command    add-module ${IMAGE_URL} 1
    ...    return_rc=True
    Should Be Equal As Integers    ${rc}  0
    &{b} =    Evaluate    ${output}
    Set Suite Variable    ${B}    ${b.module_id}
    Put File    ${CURDIR}/smtp_check.py    ${CHECK}
    ${result} =    Run on    ${A}    configure-module    {"hostname":"${HOST_A}","inbound_enabled":true,"inbound_port":25,"submission_enabled":true,"submission_port":587}
    ${result} =    Run on    ${B}    configure-module    {"hostname":"${HOST_B}","inbound_enabled":false,"submission_enabled":true,"submission_port":2587}
    ${config} =    Configuration of    ${A}
    Set Suite Variable    ${VPN_ADDR}    ${config}[node_address]
    Skip If    '${VPN_ADDR}' == ''    no cluster VPN address on this node
    Should Be Equal    ${config}[cluster_store]    none
    Should Be Equal    ${config}[cluster_status][mode]    standalone
    Should Be Empty    ${config}[warnings]
    Start the throwaway store

Check if a standalone instance renders no cluster settings
    Skip If    '${VPN_ADDR}' == ''    no cluster VPN address on this node
    ${output}  ${rc} =    In module    ${A}    grep -c -E '^ +(redis|tsa) = ' kumomta/init.lua
    Should Be Equal    ${output}    0
    ${output}  ${rc} =    In module    ${A}    systemctl --user is-enabled kumomta-cluster-check.timer kumomta-tsa.service
    Should Not Contain    ${output}    enabled

Check if an instance uses a manual store with tsa-daemon
    Skip If    '${VPN_ADDR}' == ''    no cluster VPN address on this node
    ${result} =    Run on    ${A}    configure-module    {"cluster_store":"manual","cluster_redis_nodes":["redis://${VPN_ADDR}:${VALKEY_PORT}"],"cluster_redis_username":"${ACL_USER}","cluster_redis_password":"${ACL_PASS}","tsa_enabled":true}
    ${ids} =    Evaluate    [w['id'] for w in $result['warnings']]
    Should Not Contain    ${ids}    cluster_degraded
    ${config} =    Mode is    ${A}    shared
    Should Be True    ${config}[cluster_redis_password_set]
    Should Be Empty    ${config}[warnings]
    Unit is active    ${A}    kumomta.service
    Unit is active    ${A}    kumomta-tsa.service
    Unit is active    ${A}    kumomta-cluster-check.timer
    Should Be Equal    ${config}[cluster_status][tsa_listen]    ${VPN_ADDR}:${config}[tsa_port]
    ${output}  ${rc} =    In module    ${A}    stat -c %a secrets/cluster_redis_password
    Should Be Equal    ${output}    600
    ${output}  ${rc} =    In module    ${A}    grep -rl ${ACL_PASS} kumomta settings.json environment cluster
    Should Not Be Equal As Integers    ${rc}  0
    ${output}  ${rc} =    In module    ${A}    grep -c -F 'node = "redis://${VPN_ADDR}:${VALKEY_PORT}"' kumomta/init.lua
    Should Be Equal    ${output}    1
    # tsa-daemon answers on the cluster VPN address only
    ${output} =    Execute Command    curl -s -o /dev/null -w '\%{http_code}' http://${VPN_ADDR}:${config}[tsa_port]/get_config_v1/shaping.toml
    Should Be Equal    ${output}    200
    ${output}  ${rc} =    Execute Command    curl -s -o /dev/null --max-time 5 http://127.0.0.1:${config}[tsa_port]/get_config_v1/shaping.toml
    ...    return_rc=True
    Should Not Be Equal As Integers    ${rc}  0
    # The peer record holds no secret
    ${output}  ${rc} =    In module    ${A}    python3 -c 'import agent, os; print(agent.redis_connect(use_replica=True).hgetall(os.environ["AGENT_ID"] + "/srv/tcp/kumomta-cluster"))'
    Should Contain    ${output}    'tsa': '1'
    Should Not Contain    ${output}    ${ACL_PASS}

Check if a second instance joins with cluster_join
    Skip If    '${VPN_ADDR}' == ''    no cluster VPN address on this node
    ${result} =    Run on    ${B}    configure-module    {"cluster_join":"${A}"}
    ${config} =    Mode is    ${B}    shared
    Should Be Equal    ${config}[cluster_store]    manual
    Should Be True    ${config}[tsa_enabled]
    Should Be True    ${config}[cluster_redis_password_set]
    ${peers} =    Evaluate    [p['module_id'] for p in $config['cluster_peers'] if p['same_store']]
    Should Contain    ${peers}    ${A}
    Length Should Be    ${config}[cluster_status][tsa_peers]    1
    ${output}  ${rc} =    In module    ${B}    stat -c %a secrets/cluster_redis_password
    Should Be Equal    ${output}    600
    Unit is active    ${B}    kumomta.service
    Unit is active    ${B}    kumomta-tsa.service
    # The event of the new peer makes the first instance publish to it too
    Wait Until Keyword Succeeds    2 min    10 sec    Peer daemon is listed    ${A}    1

Check if the instances share the throttle store
    Skip If    '${VPN_ADDR}' == ''    no cluster VPN address on this node
    ${result} =    Run on    ${A}    configure-module    {"sink_enabled":true,"shaping":[{"domain":"example.net","max_message_rate":"1/d"}],"smtp_users":[{"username":"ci-cluster","password":"Ci,Cluster,Pass,2026"}]}
    ${output}  ${rc} =    Execute Command    python3 ${CHECK} submit 127.0.0.1 587 ci-cluster 'Ci,Cluster,Pass,2026' ci@${CI_DOMAIN} cluster-ok@example.net
    ...    return_rc=True
    Should Be Equal As Integers    ${rc}  0    ${output}
    Wait Until Keyword Succeeds    3 min    10 sec    Store has throttle keys

Check if a store outage falls back to local throttles and keeps sending
    Skip If    '${VPN_ADDR}' == ''    no cluster VPN address on this node
    Execute Command    podman stop -t 2 kumomta-ci-valkey
    Check twice    ${B}
    ${config} =    Mode is    ${B}    local
    Should Be Equal    ${config}[cluster_status][reason]    store_unreachable
    ${ids} =    Evaluate    [w['id'] for w in $config['warnings']]
    Should Contain    ${ids}    cluster_degraded
    ${output}  ${rc} =    In module    ${B}    grep -c -E '^ +redis = ' kumomta/init.lua
    Should Be Equal    ${output}    0
    Unit is active    ${B}    kumomta.service
    ${output}  ${rc} =    Execute Command    python3 ${CHECK} banner 127.0.0.1 2587
    ...    return_rc=True
    Should Be Equal As Integers    ${rc}  0    ${output}
    # A restart while the store is down starts with local throttles
    ${output}  ${rc} =    In module    ${A}    systemctl --user restart kumomta.service
    Should Be Equal As Integers    ${rc}  0    ${output}
    Mode is    ${A}    local

Check if the instances go back to the shared store
    Skip If    '${VPN_ADDR}' == ''    no cluster VPN address on this node
    Start the throwaway store
    ${config} =    Wait Until Keyword Succeeds    1 min    5 sec    Check and expect    ${B}    shared
    Should Be Empty    ${config}[warnings]
    Wait Until Keyword Succeeds    1 min    5 sec    Check and expect    ${A}    shared
    Unit is active    ${A}    kumomta.service
    Unit is active    ${B}    kumomta.service

Check if an instance leaves the cluster
    Skip If    '${VPN_ADDR}' == ''    no cluster VPN address on this node
    ${result} =    Run on    ${B}    configure-module    {"cluster_store":"none","tsa_enabled":false}
    ${config} =    Mode is    ${B}    standalone
    Should Be Empty    ${config}[warnings]
    Should Not Be True    ${config}[cluster_redis_password_set]
    ${output}  ${rc} =    In module    ${B}    test -e secrets/cluster_redis_password
    Should Not Be Equal As Integers    ${rc}  0
    ${output}  ${rc} =    In module    ${B}    systemctl --user is-active kumomta-tsa.service kumomta-cluster-check.timer
    Should Not Match Regexp    ${output}    (?m)^active$
    Wait Until Keyword Succeeds    2 min    10 sec    Peer daemon is listed    ${A}    0

Check if an instance uses an ns8-valkey instance
    Skip If    '${VPN_ADDR}' == ''    no cluster VPN address on this node
    ${output}  ${rc} =    Execute Command    add-module ${NS8_VALKEY} 1
    ...    return_rc=True
    Should Be Equal As Integers    ${rc}  0    ${output}
    &{v} =    Evaluate    ${output}
    Set Suite Variable    ${VALKEY_ID}    ${v.module_id}
    # A one-member Valkey Cluster: ha_mode cluster with a single seed
    ${output}  ${rc} =    Execute Command    api-cli run module/${VALKEY_ID}/configure-module --data '{"role":"initial"}'
    ...    return_rc=True
    Should Be Equal As Integers    ${rc}  0    ${output}
    Wait Until Keyword Succeeds    2 min    5 sec    Valkey record is published    ${B}
    ${config} =    Configuration of    ${B}
    ${listed} =    Evaluate    [v['module_id'] for v in $config['valkey_instances']]
    Should Contain    ${listed}    ${VALKEY_ID}
    ${result} =    Run on    ${B}    configure-module    {"cluster_store":"valkey","cluster_valkey":"${VALKEY_ID}"}
    ${config} =    Mode is    ${B}    shared
    Should Be Empty    ${config}[warnings]
    Should Not Be True    ${config}[cluster_redis_password_set]
    ${output}  ${rc} =    In module    ${B}    stat -c %a secrets/cluster_redis_password
    Should Be Equal    ${output}    600
    ${output}  ${rc} =    In module    ${B}    grep -c -E '^ +cluster = true,' kumomta/init.lua
    Should Be Equal    ${output}    1
    ${output}  ${rc} =    In module    ${B}    grep -c -F 'username = "ns8c-${B}"' kumomta/init.lua
    Should Be Equal    ${output}    1
    # The granted password is in no other file (compared on the node, never printed)
    ${output}  ${rc} =    In module    ${B}    sh -c 'test -s secrets/cluster_redis_password && ! grep -rqF "$(cat secrets/cluster_redis_password)" kumomta settings.json environment cluster'
    Should Be Equal As Integers    ${rc}  0    ${output}
    Unit is active    ${B}    kumomta.service
    ${clients} =    Run on    ${VALKEY_ID}    list-clients
    ${ids} =    Evaluate    [c['client_id'] for c in $clients['clients']]
    Should Contain    ${ids}    ${B}
    # Leaving the store revokes the Valkey user
    ${result} =    Run on    ${B}    configure-module    {"cluster_store":"none"}
    Mode is    ${B}    standalone
    ${clients} =    Run on    ${VALKEY_ID}    list-clients
    ${ids} =    Evaluate    [c['client_id'] for c in $clients['clients']]
    Should Not Contain    ${ids}    ${B}

Remove the instances and the store
    Run Keyword If    '${VALKEY_ID}' != ''    Execute Command    remove-module --no-preserve ${VALKEY_ID}
    ${output}  ${rc} =    Execute Command    remove-module --no-preserve ${A}    return_rc=True
    Should Be Equal As Integers    ${rc}  0    ${output}
    ${output}  ${rc} =    Execute Command    remove-module --no-preserve ${B}    return_rc=True
    Should Be Equal As Integers    ${rc}  0    ${output}
    [Teardown]    Execute Command    podman rm -f kumomta-ci-valkey; rm -f ${CHECK}
