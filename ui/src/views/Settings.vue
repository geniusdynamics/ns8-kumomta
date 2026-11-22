<!--
  Copyright (C) 2026 Genius Dynamics
  SPDX-License-Identifier: GPL-3.0-or-later
-->
<template>
  <cv-grid fullWidth>
    <cv-row>
      <cv-column class="page-title">
        <h2>{{ $t("settings.title") }}</h2>
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
    <cv-row v-if="mailModules.length">
      <cv-column>
        <NsInlineNotification
          kind="info"
          :title="$t('settings.mail_modules_on_node')"
          :description="
            $t('settings.mail_modules_on_node_description', {
              modules: mailModules.join(', '),
            })
          "
          :showCloseButton="false"
        />
      </cv-column>
    </cv-row>
    <cv-row>
      <cv-column>
        <cv-tile light>
          <cv-form @submit.prevent="configureModule">
            <h4 class="mg-bottom">{{ $t("settings.general") }}</h4>
            <NsTextInput
              :label="$t('settings.hostname')"
              placeholder="mx.example.org"
              v-model.trim="hostname"
              :helper-text="$t('settings.hostname_helper')"
              :invalid-message="error.hostname"
              :disabled="busy"
              ref="hostname"
              class="mg-bottom maxwidth"
            />
            <NsToggle
              value="letsEncrypt"
              :label="core.$t('apps_lets_encrypt.request_https_certificate')"
              v-model="lets_encrypt"
              :disabled="busy"
              class="mg-bottom"
            >
              <template #tooltip>
                {{ $t("settings.lets_encrypt_tooltip") }}
              </template>
              <template slot="text-left">{{ $t("common.disabled") }}</template>
              <template slot="text-right">{{ $t("common.enabled") }}</template>
            </NsToggle>

            <h4 class="mg-bottom">{{ $t("settings.listeners") }}</h4>
            <NsToggle
              value="inbound"
              :label="$t('settings.inbound_enabled')"
              v-model="inbound_enabled"
              :disabled="busy"
              class="mg-bottom"
            >
              <template #tooltip>
                {{ $t("settings.inbound_tooltip") }}
              </template>
              <template slot="text-left">{{ $t("common.disabled") }}</template>
              <template slot="text-right">{{ $t("common.enabled") }}</template>
            </NsToggle>
            <NsTextInput
              v-if="inbound_enabled"
              type="number"
              :label="$t('settings.inbound_port')"
              v-model.number="inbound_port"
              :invalid-message="error.inbound_port"
              :disabled="busy"
              ref="inbound_port"
              class="mg-bottom narrow"
            />
            <NsToggle
              value="submission"
              :label="$t('settings.submission_enabled')"
              v-model="submission_enabled"
              :disabled="busy"
              class="mg-bottom"
            >
              <template #tooltip>
                {{ $t("settings.submission_tooltip") }}
              </template>
              <template slot="text-left">{{ $t("common.disabled") }}</template>
              <template slot="text-right">{{ $t("common.enabled") }}</template>
            </NsToggle>
            <NsTextInput
              v-if="submission_enabled"
              type="number"
              :label="$t('settings.submission_port')"
              v-model.number="submission_port"
              :invalid-message="error.submission_port"
              :disabled="busy"
              ref="submission_port"
              class="mg-bottom narrow"
            />
            <NsToggle
              value="implicitTls"
              :label="$t('settings.implicit_tls')"
              :checked="false"
              :disabled="true"
              class="mg-bottom"
            >
              <template #tooltip>
                {{ $t("settings.implicit_tls_tooltip") }}
              </template>
              <template slot="text-left">{{
                $t("settings.implicit_tls_unavailable")
              }}</template>
              <template slot="text-right">{{ $t("common.enabled") }}</template>
            </NsToggle>
            <NsTextInput
              type="number"
              :label="$t('settings.max_message_size')"
              v-model.number="max_message_size"
              :invalid-message="error.max_message_size"
              :disabled="busy"
              ref="max_message_size"
              class="mg-bottom narrow"
            />

            <h4 class="mg-bottom">{{ $t("settings.relay") }}</h4>
            <cv-text-area
              :label="$t('settings.relay_networks')"
              v-model="relayNetworksText"
              :helper-text="$t('settings.relay_networks_helper')"
              :invalid-message="error.relay_networks"
              :disabled="busy"
              ref="relay_networks"
              class="mg-bottom maxwidth"
              placeholder="192.168.1.0/24"
            />
            <NsToggle
              value="clusterRelay"
              :label="$t('settings.cluster_relay')"
              v-model="cluster_relay"
              :disabled="busy"
              class="mg-bottom"
            >
              <template #tooltip>
                {{ $t("settings.cluster_relay_tooltip") }}
              </template>
              <template slot="text-left">{{ $t("common.disabled") }}</template>
              <template slot="text-right">{{ $t("common.enabled") }}</template>
            </NsToggle>
            <NsInlineNotification
              v-if="!cluster_relay"
              kind="info"
              :title="$t('settings.cluster_relay_off')"
              :description="$t('settings.cluster_relay_off_description')"
              :showCloseButton="false"
            />
            <NsInlineNotification
              v-else-if="!(inbound_enabled && inbound_port == 25)"
              kind="warning"
              :title="$t('settings.cluster_relay_needs_port_25')"
              :description="
                $t('settings.cluster_relay_needs_port_25_description')
              "
              :showCloseButton="false"
            />
            <NsInlineNotification
              v-else-if="cluster_relay_active"
              kind="info"
              :title="$t('settings.cluster_relay_active')"
              :description="
                $t('settings.cluster_relay_active_description', {
                  network: cluster_network,
                  address: node_address,
                })
              "
              :showCloseButton="false"
            />
            <NsToggle
              value="trustLoopback"
              :label="$t('settings.trust_loopback')"
              v-model="trust_loopback"
              :disabled="busy"
              class="mg-bottom"
            >
              <template #tooltip>
                {{ $t("settings.trust_loopback_tooltip") }}
              </template>
              <template slot="text-left">{{ $t("common.disabled") }}</template>
              <template slot="text-right">{{ $t("common.enabled") }}</template>
            </NsToggle>

            <h4 class="mg-bottom">{{ $t("settings.queues") }}</h4>
            <NsTextInput
              :label="$t('settings.retry_interval')"
              v-model.trim="retry_interval"
              :helper-text="$t('settings.duration_helper')"
              :invalid-message="error.retry_interval"
              :disabled="busy"
              ref="retry_interval"
              class="mg-bottom narrow"
            />
            <NsTextInput
              :label="$t('settings.max_age')"
              v-model.trim="max_age"
              :helper-text="$t('settings.duration_helper')"
              :invalid-message="error.max_age"
              :disabled="busy"
              ref="max_age"
              class="mg-bottom narrow"
            />

            <h4 class="mg-bottom">{{ $t("settings.testing") }}</h4>
            <NsToggle
              value="sink"
              :label="$t('settings.sink_enabled')"
              v-model="sink_enabled"
              :disabled="busy"
              class="mg-bottom"
            >
              <template #tooltip>
                {{ $t("settings.sink_tooltip") }}
              </template>
              <template slot="text-left">{{ $t("common.disabled") }}</template>
              <template slot="text-right">{{ $t("common.enabled") }}</template>
            </NsToggle>
            <NsInlineNotification
              v-if="sink_enabled"
              kind="warning"
              :title="$t('warnings.sink_mode_title')"
              :description="$t('settings.sink_description')"
              :showCloseButton="false"
            />

            <cv-accordion class="mg-bottom maxwidth">
              <cv-accordion-item :open="false">
                <template slot="title">{{ $t("settings.metrics") }}</template>
                <template slot="content">
                  <p class="mg-bottom">
                    {{ $t("settings.metrics_description") }}
                  </p>
                  <NsTextInput
                    :label="$t('settings.metrics_host')"
                    placeholder="mta-metrics.example.org"
                    v-model.trim="metrics_host"
                    :invalid-message="error.metrics_host"
                    :disabled="busy"
                    ref="metrics_host"
                    class="mg-bottom"
                  />
                  <NsTextInput
                    v-if="metrics_host"
                    type="password"
                    autocomplete="new-password"
                    :label="$t('settings.metrics_password')"
                    v-model="metrics_password"
                    :placeholder="
                      metrics_password_set ? $t('common.unchanged') : ''
                    "
                    :invalid-message="error.metrics_password"
                    :disabled="busy"
                    ref="metrics_password"
                    class="mg-bottom"
                  />
                  <NsToggle
                    v-if="metrics_host"
                    value="metricsPublic"
                    :label="$t('settings.metrics_public')"
                    v-model="metrics_public"
                    :disabled="busy"
                    class="mg-bottom"
                  >
                    <template #tooltip>
                      {{ $t("settings.metrics_public_tooltip") }}
                    </template>
                    <template slot="text-left">{{
                      $t("common.disabled")
                    }}</template>
                    <template slot="text-right">{{
                      $t("common.enabled")
                    }}</template>
                  </NsToggle>
                  <cv-text-area
                    v-if="metrics_host"
                    :label="$t('settings.metrics_allowlist')"
                    v-model="metricsAllowlistText"
                    :helper-text="$t('settings.metrics_allowlist_helper')"
                    :invalid-message="error.metrics_allowlist"
                    :disabled="busy"
                    ref="metrics_allowlist"
                  />
                </template>
              </cv-accordion-item>
            </cv-accordion>

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
  name: "Settings",
  mixins: [
    TaskService,
    IconService,
    UtilService,
    QueryParamService,
    PageTitleService,
    ModuleTask,
  ],
  pageTitle() {
    return this.$t("settings.title") + " - " + this.appName;
  },
  data() {
    return {
      q: { page: "settings" },
      urlCheckInterval: null,
      hostname: "",
      lets_encrypt: false,
      inbound_enabled: true,
      inbound_port: 25,
      submission_enabled: true,
      submission_port: 587,
      max_message_size: 25,
      relayNetworksText: "",
      cluster_relay: true,
      cluster_relay_active: false,
      trust_loopback: true,
      sink_enabled: false,
      cluster_network: "",
      node_address: "",
      retry_interval: "20m",
      max_age: "5d",
      metrics_host: "",
      metrics_password: "",
      metrics_password_set: false,
      metrics_public: true,
      metricsAllowlistText: "",
      mailModules: [],
      loading: { getConfiguration: false, configureModule: false },
      error: {
        getConfiguration: "",
        configureModule: "",
        hostname: "",
        inbound_port: "",
        inbound_enabled: "",
        submission_port: "",
        max_message_size: "",
        relay_networks: "",
        retry_interval: "",
        max_age: "",
        metrics_host: "",
        metrics_password: "",
        metrics_allowlist: "",
      },
    };
  },
  computed: {
    ...mapState(["instanceName", "core", "appName"]),
    busy() {
      return this.loading.getConfiguration || this.loading.configureModule;
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
    async getConfiguration() {
      this.loading.getConfiguration = true;
      this.error.getConfiguration = "";
      try {
        const c = await this.runModuleTask("get-configuration");
        this.hostname = c.hostname;
        this.lets_encrypt = c.lets_encrypt;
        this.inbound_enabled = c.inbound_enabled;
        this.inbound_port = c.inbound_port;
        this.submission_enabled = c.submission_enabled;
        this.submission_port = c.submission_port;
        this.max_message_size = c.max_message_size;
        this.relayNetworksText = c.relay_networks.join("\n");
        this.cluster_relay = c.cluster_relay;
        this.trust_loopback = c.trust_loopback;
        this.sink_enabled = c.sink_enabled;
        this.cluster_relay_active = c.cluster_relay_active;
        this.cluster_network = c.cluster_network;
        this.node_address = c.node_address;
        this.retry_interval = c.retry_interval;
        this.max_age = c.max_age;
        this.metrics_host = c.metrics_host;
        this.metrics_password_set = c.metrics_password_set;
        this.metricsAllowlistText = c.metrics_allowlist.join("\n");
        this.metrics_public = c.metrics_public !== false;
        this.mailModules = c.mail_modules;
        this.focusElement("hostname");
      } catch (failure) {
        this.error.getConfiguration = this.taskErrorMessage(failure);
      }
      this.loading.getConfiguration = false;
    },
    validate() {
      this.clearErrors(this);
      if (!this.hostname) {
        this.error.hostname = this.$t("common.required");
        this.focusElement("hostname");
        return false;
      }
      if (!this.inbound_enabled && !this.submission_enabled) {
        this.error.configureModule = this.$t("validation.no_listener_enabled");
        return false;
      }
      return true;
    },
    async configureModule() {
      if (!this.validate()) {
        return;
      }
      this.loading.configureModule = true;
      const data = {
        hostname: this.hostname,
        lets_encrypt: this.lets_encrypt,
        inbound_enabled: this.inbound_enabled,
        inbound_port: parseInt(this.inbound_port),
        submission_enabled: this.submission_enabled,
        submission_port: parseInt(this.submission_port),
        max_message_size: parseInt(this.max_message_size),
        relay_networks: this.linesToList(this.relayNetworksText),
        cluster_relay: this.cluster_relay,
        trust_loopback: this.trust_loopback,
        sink_enabled: this.sink_enabled,
        retry_interval: this.retry_interval,
        max_age: this.max_age,
        metrics_host: this.metrics_host,
        metrics_public: this.metrics_public,
        metrics_allowlist: this.linesToList(this.metricsAllowlistText),
      };
      if (this.metrics_password) {
        data.metrics_password = this.metrics_password;
      }
      try {
        await this.runModuleTask("configure-module", data, {
          title: this.$t("settings.configure_instance", {
            instance: this.instanceName,
          }),
          hidden: false,
        });
        this.metrics_password = "";
        this.getConfiguration();
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
.maxwidth {
  max-width: 38rem;
}
.narrow {
  max-width: 16rem;
}
</style>
