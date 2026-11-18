<!--
  Copyright (C) 2026 Genius Dynamics
  SPDX-License-Identifier: GPL-3.0-or-later
-->
<template>
  <cv-grid fullWidth>
    <cv-row>
      <cv-column class="page-title">
        <h2>{{ $t("cluster.title") }}</h2>
      </cv-column>
    </cv-row>
    <cv-row v-if="error.getConfiguration">
      <cv-column>
        <NsInlineNotification
          kind="error"
          :title="$t('action.get-configuration')"
          :description="error.getConfiguration"
          :showCloseButton="false"
        />
      </cv-column>
    </cv-row>
    <!-- status of a clustered instance -->
    <cv-row v-if="status.mode !== 'standalone' || tsaSaved">
      <cv-column>
        <cv-tile light class="mg-bottom">
          <h4 class="mg-bottom-sm">{{ $t("cluster.status_title") }}</h4>
          <div class="facts">
            <div class="fact">
              <span class="label">{{ $t("cluster.throttles") }}</span>
              <NsTag
                :kind="
                  status.mode === 'shared'
                    ? 'green'
                    : status.mode === 'local'
                    ? 'red'
                    : 'gray'
                "
                :label="$t('cluster.mode_' + status.mode)"
              />
            </div>
            <div v-if="status.store" class="fact">
              <span class="label">{{ $t("cluster.store") }}</span>
              <span>{{ status.store }}</span>
            </div>
            <div v-if="status.tsa_listen" class="fact">
              <span class="label">{{ $t("cluster.tsa_listen") }}</span>
              <span>{{ status.tsa_listen }}</span>
            </div>
            <div v-if="status.mode !== 'standalone'" class="fact">
              <span class="label">{{ $t("cluster.tsa_hosts") }}</span>
              <span>{{
                (status.tsa_hosts || []).join(", ") || $t("cluster.none")
              }}</span>
            </div>
            <div v-if="status.mode !== 'standalone'" class="fact">
              <span class="label">{{ $t("cluster.tsa_peers") }}</span>
              <span>{{
                (status.tsa_peers || []).join(", ") || $t("cluster.none")
              }}</span>
            </div>
          </div>
          <NsInlineNotification
            v-if="status.mode === 'local'"
            kind="warning"
            :title="$t('warnings.cluster_degraded_title')"
            :description="
              $t('cluster.reason_' + status.reason, { store: status.store })
            "
            :showCloseButton="false"
          />
          <NsInlineNotification
            v-if="tsaUnreachable"
            kind="warning"
            :title="$t('cluster.tsa_unreachable_title')"
            :description="$t('cluster.tsa_unreachable_description')"
            :showCloseButton="false"
          />
          <template v-if="samePeers.length">
            <div class="label">{{ $t("cluster.peers") }}</div>
            <ul class="peers">
              <li v-for="peer in samePeers" :key="peer.module_id">
                {{ peerLabel(peer) }}
                <NsTag
                  :kind="peer.mode === 'shared' ? 'green' : 'red'"
                  size="sm"
                  :label="$t('cluster.mode_' + (peer.mode || 'local'))"
                />
              </li>
            </ul>
          </template>
        </cv-tile>
      </cv-column>
    </cv-row>
    <cv-row v-if="peers.length">
      <cv-column>
        <cv-tile light class="mg-bottom">
          <h4 class="mg-bottom-sm">{{ $t("cluster.peer_access") }}</h4>
          <p class="mg-bottom-sm description">
            {{ $t("cluster.peer_access_description") }}
          </p>
          <ul class="access-list maxwidth">
            <li v-for="peer in peers" :key="peer.module_id">
              <span :id="'peer-access-' + peer.module_id">{{
                peerLabel(peer)
              }}</span>
              <NsButton
                kind="tertiary"
                size="small"
                :aria-describedby="'peer-access-' + peer.module_id"
                :disabled="busy"
                :loading="loading.peerAccess === peer.module_id"
                @click="setPeerAccess(peer)"
              >
                {{
                  $t(
                    peer.secret_access
                      ? "cluster.revoke_access"
                      : "cluster.allow_access"
                  )
                }}
              </NsButton>
            </li>
          </ul>
          <NsInlineNotification
            v-if="error.peerAccess"
            kind="error"
            :title="$t('action.set-peer-access')"
            :description="error.peerAccess"
            :showCloseButton="false"
          />
        </cv-tile>
      </cv-column>
    </cv-row>
    <cv-row>
      <cv-column>
        <cv-tile light>
          <p class="mg-bottom">{{ $t("cluster.description") }}</p>
          <cv-form @submit.prevent="save">
            <cv-radio-group
              :legend="$t('cluster.store_choice')"
              vertical
              class="mg-bottom"
              ref="cluster_store"
            >
              <cv-radio-button
                :label="$t('cluster.choice_none')"
                value="none"
                v-model="choice"
                :disabled="busy"
              />
              <p class="radio-description">
                {{ $t("cluster.choice_none_description") }}
              </p>
              <cv-radio-button
                :label="$t('cluster.choice_join')"
                value="join"
                v-model="choice"
                :disabled="busy || !joinablePeers.length"
              />
              <p class="radio-description">
                {{ $t("cluster.choice_join_description") }}
              </p>
              <cv-radio-button
                :label="$t('cluster.choice_valkey')"
                value="valkey"
                v-model="choice"
                :disabled="busy"
              />
              <p class="radio-description">
                {{ $t("cluster.choice_valkey_description") }}
              </p>
              <cv-radio-button
                :label="$t('cluster.choice_manual')"
                value="manual"
                v-model="choice"
                :disabled="busy"
              />
              <p class="radio-description">
                {{ $t("cluster.choice_manual_description") }}
              </p>
            </cv-radio-group>

            <div v-if="choice === 'join'" class="maxwidth mg-bottom">
              <NsComboBox
                v-model="cluster_join"
                :options="joinOptions"
                :title="$t('cluster.join_peer')"
                :label="$t('cluster.choose')"
                :invalid-message="error.cluster_join"
                :disabled="busy"
                :auto-filter="true"
                :auto-highlight="true"
                ref="cluster_join"
              />
            </div>

            <div v-if="choice === 'valkey'" class="maxwidth mg-bottom">
              <NsComboBox
                v-if="valkeyOptions.length"
                v-model="cluster_valkey"
                :options="valkeyOptions"
                :title="$t('cluster.valkey_instance')"
                :label="$t('cluster.choose')"
                :invalid-message="error.cluster_valkey"
                :disabled="busy"
                :auto-filter="true"
                :auto-highlight="true"
                ref="cluster_valkey"
              />
              <NsInlineNotification
                v-else
                kind="info"
                :title="$t('cluster.no_valkey_title')"
                :description="$t('cluster.no_valkey_description')"
                :showCloseButton="false"
              />
            </div>

            <template v-if="choice === 'manual'">
              <cv-text-area
                :label="$t('cluster.redis_nodes')"
                v-model="nodesText"
                placeholder="redis://10.0.0.5:6379"
                :helper-text="$t('cluster.redis_nodes_helper')"
                :invalid-message="error.cluster_redis_nodes"
                :disabled="busy"
                ref="cluster_redis_nodes"
                class="mg-bottom maxwidth"
              />
              <NsToggle
                value="redisCluster"
                :label="$t('cluster.redis_cluster')"
                v-model="cluster_redis_cluster"
                :disabled="busy"
                class="mg-bottom"
              >
                <template #tooltip>{{
                  $t("cluster.redis_cluster_tooltip")
                }}</template>
                <template slot="text-left">{{
                  $t("common.disabled")
                }}</template>
                <template slot="text-right">{{
                  $t("common.enabled")
                }}</template>
              </NsToggle>
              <NsTextInput
                :label="$t('cluster.redis_username')"
                v-model.trim="cluster_redis_username"
                :helper-text="$t('cluster.redis_username_helper')"
                :invalid-message="error.cluster_redis_username"
                :disabled="busy"
                ref="cluster_redis_username"
                class="mg-bottom narrow"
              />
              <NsTextInput
                type="password"
                autocomplete="new-password"
                :label="$t('cluster.redis_password')"
                v-model="cluster_redis_password"
                :placeholder="
                  cluster_redis_password_set ? $t('common.unchanged') : ''
                "
                :helper-text="
                  vault_enabled
                    ? $t('cluster.redis_password_openbao_helper')
                    : $t('cluster.redis_password_helper')
                "
                :invalid-message="error.cluster_redis_password"
                :disabled="busy"
                ref="cluster_redis_password"
                class="mg-bottom maxwidth"
              />
            </template>

            <h4 class="mg-bottom-sm">{{ $t("cluster.tsa_title") }}</h4>
            <p v-if="choice !== 'none'" class="mg-bottom-sm description">
              {{ $t("cluster.tsa_designation_description") }}
            </p>
            <NsCheckbox
              :label="
                choice === 'none'
                  ? $t('cluster.tsa_enabled')
                  : $t('cluster.tsa_designated')
              "
              v-model="tsa_enabled"
              :disabled="busy"
              value="tsaDesignated"
              class="mg-bottom-sm"
            />
            <NsInlineNotification
              v-if="designationChange"
              kind="warning"
              :title="$t('cluster.tsa_change_title')"
              :description="
                $t('cluster.tsa_change_description', {
                  peers: samePeers.map((p) => p.module_id).join(', '),
                })
              "
              :showCloseButton="false"
              class="maxwidth"
            />
            <NsInlineNotification
              v-if="lastTsaHostLeaving"
              kind="warning"
              :title="$t('cluster.tsa_last_host_title')"
              :description="$t('cluster.tsa_last_host_description')"
              :showCloseButton="false"
              class="maxwidth"
            />
            <NsInlineNotification
              v-if="choice !== 'none' && savedStore === 'none'"
              kind="info"
              :title="$t('cluster.join_notice_title')"
              :description="$t('cluster.join_notice_description')"
              :showCloseButton="false"
              class="maxwidth"
            />
            <NsInlineNotification
              v-if="error.configureModule"
              kind="error"
              :title="$t('action.configure-module')"
              :description="error.configureModule"
              :showCloseButton="false"
            />
            <NsButton
              kind="primary"
              :icon="Save20"
              :loading="loading.configureModule"
              :disabled="busy"
              >{{ $t("common.save") }}</NsButton
            >
          </cv-form>
        </cv-tile>
      </cv-column>
    </cv-row>
  </cv-grid>
</template>

<script>
import { mapState } from "vuex";
import {
  QueryParamService,
  UtilService,
  TaskService,
  IconService,
  PageTitleService,
} from "@nethserver/ns8-ui-lib";
import ModuleTask from "@/mixins/moduleTask";

export default {
  name: "Cluster",
  mixins: [
    TaskService,
    IconService,
    UtilService,
    QueryParamService,
    PageTitleService,
    ModuleTask,
  ],
  pageTitle() {
    return this.$t("cluster.title") + " - " + this.appName;
  },
  data() {
    return {
      q: { page: "cluster" },
      urlCheckInterval: null,
      // none, join (copy the settings of a peer), valkey, manual
      choice: "none",
      savedStore: "none",
      cluster_join: "",
      cluster_valkey: "",
      nodesText: "",
      cluster_redis_username: "",
      cluster_redis_password: "",
      cluster_redis_password_set: false,
      cluster_redis_cluster: false,
      tsa_enabled: false,
      tsaSaved: false,
      vault_enabled: false,
      status: { mode: "standalone", reason: "", tsa_peers: [] },
      valkeyInstances: [],
      peers: [],
      loading: {
        getConfiguration: false,
        configureModule: false,
        peerAccess: "",
      },
      error: {
        getConfiguration: "",
        configureModule: "",
        peerAccess: "",
        cluster_store: "",
        cluster_join: "",
        cluster_valkey: "",
        cluster_redis_nodes: "",
        cluster_redis_username: "",
        cluster_redis_password: "",
        tsa_enabled: "",
      },
    };
  },
  computed: {
    ...mapState(["instanceName", "core", "appName"]),
    busy() {
      return (
        this.loading.getConfiguration ||
        this.loading.configureModule ||
        !!this.loading.peerAccess
      );
    },
    valkeyOptions() {
      return this.valkeyInstances.map((v) => ({
        name: v.module_id,
        value: v.module_id,
        label: `${v.ui_name || v.module_id} (${v.module_id}, ${v.endpoint})`,
      }));
    },
    joinablePeers() {
      return this.peers.filter((p) => p.clustered);
    },
    joinOptions() {
      return this.joinablePeers.map((p) => ({
        name: p.module_id,
        value: p.module_id,
        label: this.peerLabel(p),
      }));
    },
    samePeers() {
      return this.peers.filter((p) => p.same_store);
    },
    // Changing the designation restarts kumod once on the peers of the
    // same store: their list of tsa-daemons changes
    designationChange() {
      return (
        this.savedStore !== "none" &&
        this.choice === this.savedStore &&
        this.tsa_enabled !== this.tsaSaved &&
        this.samePeers.length > 0
      );
    },
    lastTsaHostLeaving() {
      const hosts = this.status.tsa_hosts || [];
      return (
        this.savedStore !== "none" &&
        this.tsaSaved &&
        !this.tsa_enabled &&
        hosts.filter((h) => h !== this.instanceName).length === 0
      );
    },
    tsaUnreachable() {
      return (
        (this.status.tsa_hosts || []).length > 0 &&
        this.status.mode !== "standalone" &&
        !this.status.tsa_reachable
      );
    },
  },
  created() {
    this.getConfiguration();
  },
  beforeRouteEnter(to, from, next) {
    next((vm) => {
      vm.watchQueryData(vm);
      vm.urlCheckInterval = vm.initUrlBindingForApp(vm, vm.q.page);
    });
  },
  beforeRouteLeave(to, from, next) {
    clearInterval(this.urlCheckInterval);
    next();
  },
  methods: {
    peerLabel(peer) {
      const name = peer.ui_name || peer.module_id;
      const host = peer.hostname ? `, ${peer.hostname}` : "";
      return `${name} (${peer.module_id}, ${this.$t("cluster.node")} ${
        peer.node
      }${host})`;
    },
    async setPeerAccess(peer) {
      this.error.peerAccess = "";
      this.loading.peerAccess = peer.module_id;
      try {
        const result = await this.runModuleTask("set-peer-access", {
          peer: peer.module_id,
          allowed: !peer.secret_access,
        });
        this.$set(peer, "secret_access", result.allowed);
      } catch (failure) {
        this.error.peerAccess = this.taskErrorMessage(failure);
      } finally {
        this.loading.peerAccess = "";
      }
    },
    async getConfiguration() {
      this.loading.getConfiguration = true;
      this.error.getConfiguration = "";
      try {
        const c = await this.runModuleTask("get-configuration");
        this.choice = c.cluster_store;
        this.savedStore = c.cluster_store;
        this.cluster_valkey = c.cluster_valkey;
        this.nodesText = (c.cluster_redis_nodes || []).join("\n");
        this.cluster_redis_username = c.cluster_redis_username;
        this.cluster_redis_password_set = c.cluster_redis_password_set;
        this.cluster_redis_cluster = c.cluster_redis_cluster;
        this.tsa_enabled = c.tsa_enabled;
        this.tsaSaved = c.tsa_enabled;
        this.vault_enabled = c.vault_enabled;
        this.status = c.cluster_status;
        this.valkeyInstances = c.valkey_instances || [];
        this.peers = c.cluster_peers || [];
      } catch (failure) {
        this.error.getConfiguration = this.taskErrorMessage(failure);
      }
      this.loading.getConfiguration = false;
    },
    async save() {
      this.clearErrors(this);
      let data = { tsa_enabled: this.tsa_enabled };
      if (this.choice === "join") {
        if (!this.cluster_join) {
          this.error.cluster_join = this.$t("common.required");
          this.focusElement("cluster_join");
          return;
        }
        data = {
          cluster_join: this.cluster_join,
          tsa_enabled: this.tsa_enabled,
        };
      } else if (this.choice === "valkey") {
        if (!this.cluster_valkey) {
          this.error.cluster_valkey = this.$t("common.required");
          return;
        }
        data.cluster_store = "valkey";
        data.cluster_valkey = this.cluster_valkey;
      } else if (this.choice === "manual") {
        const nodes = this.linesToList(this.nodesText);
        if (!nodes.length) {
          this.error.cluster_redis_nodes = this.$t("common.required");
          this.focusElement("cluster_redis_nodes");
          return;
        }
        data.cluster_store = "manual";
        data.cluster_redis_nodes = nodes;
        data.cluster_redis_username = this.cluster_redis_username;
        data.cluster_redis_cluster = this.cluster_redis_cluster;
        if (this.cluster_redis_password) {
          data.cluster_redis_password = this.cluster_redis_password;
        }
      } else {
        data.cluster_store = "none";
      }
      this.loading.configureModule = true;
      try {
        await this.runModuleTask("configure-module", data, {
          title: this.$t("cluster.saving"),
          hidden: false,
        });
        this.cluster_redis_password = "";
        this.cluster_join = "";
        // refreshes the warnings of the store (banner) too
        await this.getConfiguration();
      } catch (failure) {
        this.error.configureModule = this.taskErrorMessage(failure);
      }
      this.loading.configureModule = false;
    },
  },
};
</script>

<style scoped lang="scss">
@import "../styles/carbon-utils";
.mg-bottom {
  margin-bottom: $spacing-06;
}
.mg-bottom-sm {
  margin-bottom: $spacing-05;
}
.maxwidth {
  max-width: 38rem;
}
.narrow {
  max-width: 16rem;
}
.label {
  font-size: 0.75rem;
  margin-bottom: $spacing-03;
  margin-right: $spacing-05;
  color: $text-02;
}
.facts {
  margin-bottom: $spacing-05;
}
.fact {
  display: flex;
  align-items: center;
  margin-bottom: $spacing-03;
}
.fact .label {
  min-width: 12rem;
  margin-bottom: 0;
}
.radio-description {
  margin: 0 0 $spacing-04 $spacing-07;
  color: $text-02;
  font-size: 0.875rem;
}
.description {
  color: $text-02;
  max-width: 38rem;
}
.peers {
  list-style: disc;
  padding-left: $spacing-06;
}
.peers li {
  margin-bottom: $spacing-03;
}
.access-list li {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: space-between;
  gap: $spacing-03 $spacing-05;
  margin-bottom: $spacing-03;
}
</style>
