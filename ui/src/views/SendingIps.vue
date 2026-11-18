<!--
  Copyright (C) 2026 Genius Dynamics
  SPDX-License-Identifier: GPL-3.0-or-later
-->
<template>
  <cv-grid fullWidth>
    <cv-row>
      <cv-column class="page-title">
        <h2>{{ $t("sending_ips.title") }}</h2>
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
    <cv-row>
      <cv-column>
        <cv-tile light>
          <p class="mg-bottom">{{ $t("sending_ips.description") }}</p>
          <NsInlineNotification
            v-if="clustered"
            kind="info"
            :title="$t('sending_ips.cluster_title')"
            :description="$t('sending_ips.cluster_description')"
            :showCloseButton="false"
          />
          <cv-form @submit.prevent="save">
            <div v-for="(ip, index) in ips" :key="ip.key" class="ip-box">
              <div class="row-fields">
                <NsTextInput
                  :label="$t('sending_ips.address')"
                  v-model.trim="ip.address"
                  :placeholder="$t('sending_ips.address_placeholder')"
                  :disabled="busy"
                  class="address"
                />
                <NsTextInput
                  :label="$t('sending_ips.ehlo_domain')"
                  v-model.trim="ip.ehlo_domain"
                  :placeholder="hostname"
                  :disabled="busy"
                  class="address"
                />
                <NsTextInput
                  type="number"
                  :label="$t('sending_ips.weight')"
                  v-model.number="ip.weight"
                  :disabled="busy"
                  class="number"
                />
              </div>
              <div class="label">{{ $t("sending_ips.overall_limits") }}</div>
              <div class="row-fields">
                <NsTextInput
                  v-for="field in limitFields"
                  :key="field"
                  type="number"
                  :label="$t('sending_ips.' + field)"
                  v-model.number="ip[field]"
                  :disabled="busy"
                  class="number"
                />
              </div>
              <div class="label">{{ $t("sending_ips.provider_limits") }}</div>
              <cv-structured-list
                v-if="ip.providers.length"
                condensed
                class="providers"
              >
                <template slot="headings">
                  <cv-structured-list-heading>{{
                    $t("sending_ips.provider")
                  }}</cv-structured-list-heading>
                  <cv-structured-list-heading
                    v-for="field in limitFields"
                    :key="field"
                    >{{
                      $t("sending_ips." + field)
                    }}</cv-structured-list-heading
                  >
                  <cv-structured-list-heading></cv-structured-list-heading>
                </template>
                <template slot="items">
                  <cv-structured-list-item
                    v-for="(rule, rindex) in ip.providers"
                    :key="rule.key"
                  >
                    <cv-structured-list-data>
                      <NsComboBox
                        v-model="rule.provider"
                        :options="providerOptions"
                        :title="''"
                        :label="$t('cluster.choose')"
                        :auto-filter="false"
                        :auto-highlight="true"
                        :disabled="busy"
                      />
                      <NsTextInput
                        v-if="
                          rule.provider === 'domain' || rule.provider === 'mx'
                        "
                        v-model.trim="rule.match"
                        :placeholder="
                          rule.provider === 'mx'
                            ? 'mx.example.net'
                            : 'example.com'
                        "
                        :disabled="busy"
                      />
                    </cv-structured-list-data>
                    <cv-structured-list-data
                      v-for="field in limitFields"
                      :key="field"
                    >
                      <NsTextInput
                        type="number"
                        v-model.number="rule[field]"
                        :disabled="busy"
                        class="number"
                      />
                    </cv-structured-list-data>
                    <cv-structured-list-data>
                      <NsButton
                        kind="ghost"
                        size="small"
                        :icon="TrashCan20"
                        :disabled="busy"
                        @click="ip.providers.splice(rindex, 1)"
                        >{{ $t("common.remove") }}</NsButton
                      >
                    </cv-structured-list-data>
                  </cv-structured-list-item>
                </template>
              </cv-structured-list>
              <div class="buttons">
                <NsButton
                  kind="tertiary"
                  size="small"
                  :icon="Add20"
                  :disabled="busy"
                  @click="addProvider(ip)"
                  >{{ $t("sending_ips.add_provider") }}</NsButton
                >
                <NsButton
                  kind="tertiary"
                  size="small"
                  :icon="Add20"
                  :disabled="busy"
                  @click="addPresets(ip)"
                  >{{ $t("sending_ips.add_presets") }}</NsButton
                >
                <NsButton
                  kind="ghost"
                  size="small"
                  :icon="TrashCan20"
                  :disabled="busy"
                  @click="ips.splice(index, 1)"
                  >{{ $t("sending_ips.remove_ip") }}</NsButton
                >
              </div>
            </div>
            <NsButton
              kind="secondary"
              :icon="Add20"
              :disabled="busy"
              class="mg-bottom"
              @click="addIp"
              >{{ $t("sending_ips.add_ip") }}</NsButton
            >
            <NsInlineNotification
              v-if="error.configureModule"
              kind="error"
              :title="$t('action.configure-module')"
              :description="error.configureModule"
              :showCloseButton="false"
            />
            <div>
              <NsButton
                kind="primary"
                :icon="Save20"
                :loading="loading.configureModule"
                :disabled="busy"
                >{{ $t("common.save") }}</NsButton
              >
            </div>
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

const LIMIT_FIELDS = ["per_minute", "per_hour", "per_day", "max_connections"];

// Starting points per sending IP for the large mailbox providers:
// conservative, to be raised as the reputation of the IP grows
const PRESETS = {
  google: { per_minute: 0, per_hour: 2000, per_day: 0, max_connections: 5 },
  outlook: { per_minute: 0, per_hour: 1000, per_day: 0, max_connections: 3 },
  office365: {
    per_minute: 0,
    per_hour: 2000,
    per_day: 0,
    max_connections: 5,
  },
  yahoo: { per_minute: 0, per_hour: 1000, per_day: 0, max_connections: 3 },
  apple: { per_minute: 0, per_hour: 500, per_day: 0, max_connections: 3 },
};

export default {
  name: "SendingIps",
  mixins: [
    TaskService,
    IconService,
    UtilService,
    QueryParamService,
    PageTitleService,
    ModuleTask,
  ],
  pageTitle() {
    return this.$t("sending_ips.title") + " - " + this.appName;
  },
  data() {
    return {
      q: { page: "sending-ips" },
      urlCheckInterval: null,
      limitFields: LIMIT_FIELDS,
      ips: [],
      presets: [],
      hostname: "",
      clustered: false,
      loading: { getConfiguration: false, configureModule: false },
      error: { getConfiguration: "", configureModule: "", sending_ips: "" },
    };
  },
  computed: {
    ...mapState(["instanceName", "core", "appName"]),
    busy() {
      return this.loading.getConfiguration || this.loading.configureModule;
    },
    providerOptions() {
      return this.presets
        .map((p) => ({ name: p.provider, value: p.provider, label: p.label }))
        .concat([
          {
            name: "domain",
            value: "domain",
            label: this.$t("sending_ips.provider_domain"),
          },
          {
            name: "mx",
            value: "mx",
            label: this.$t("sending_ips.provider_mx"),
          },
        ]);
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
    limits(source) {
      const out = {};
      for (const field of LIMIT_FIELDS) {
        out[field] = Number((source && source[field]) || 0);
      }
      return out;
    },
    async getConfiguration() {
      this.loading.getConfiguration = true;
      this.error.getConfiguration = "";
      try {
        const c = await this.runModuleTask("get-configuration");
        this.hostname = c.hostname;
        this.clustered = c.cluster_store !== "none";
        this.presets = c.provider_presets || [];
        this.ips = (c.sending_ips || []).map((ip) =>
          Object.assign(
            {
              key: this.getUuid(),
              address: ip.address || "",
              ehlo_domain: ip.ehlo_domain || "",
              weight: ip.weight || 1,
              providers: (ip.providers || []).map((r) =>
                Object.assign(
                  {
                    key: this.getUuid(),
                    provider: r.provider,
                    match: r.match || "",
                  },
                  this.limits(r)
                )
              ),
            },
            this.limits(ip)
          )
        );
      } catch (failure) {
        this.error.getConfiguration = this.taskErrorMessage(failure);
      }
      this.loading.getConfiguration = false;
    },
    addIp() {
      this.ips.push(
        Object.assign(
          {
            key: this.getUuid(),
            address: "",
            ehlo_domain: "",
            weight: 1,
            providers: [],
          },
          this.limits(null)
        )
      );
    },
    addProvider(ip) {
      ip.providers.push(
        Object.assign(
          { key: this.getUuid(), provider: "domain", match: "" },
          this.limits(null)
        )
      );
    },
    addPresets(ip) {
      for (const [provider, values] of Object.entries(PRESETS)) {
        if (!ip.providers.some((r) => r.provider === provider)) {
          ip.providers.push(
            Object.assign(
              { key: this.getUuid(), provider, match: "" },
              this.limits(values)
            )
          );
        }
      }
    },
    async save() {
      this.clearErrors(this);
      const data = {
        sending_ips: this.ips.map((ip) =>
          Object.assign(
            {
              address: ip.address,
              ehlo_domain: ip.ehlo_domain,
              weight: Number(ip.weight) || 1,
              providers: ip.providers.map((r) =>
                Object.assign(
                  {
                    provider: r.provider,
                    match:
                      r.provider === "domain" || r.provider === "mx"
                        ? r.match
                        : "",
                  },
                  this.limits(r)
                )
              ),
            },
            this.limits(ip)
          )
        ),
      };
      this.loading.configureModule = true;
      try {
        await this.runModuleTask("configure-module", data, {
          title: this.$t("sending_ips.saving"),
          hidden: false,
        });
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
.ip-box {
  border: 1px solid $ui-03;
  padding: $spacing-05;
  margin-bottom: $spacing-06;
  max-width: 72rem;
}
.row-fields {
  display: flex;
  flex-wrap: wrap;
  gap: $spacing-05;
  align-items: flex-end;
  margin-bottom: $spacing-05;
}
.address {
  max-width: 18rem;
}
.number {
  max-width: 9rem;
}
.label {
  font-size: 0.75rem;
  margin-bottom: $spacing-03;
  color: $text-02;
}
.providers {
  margin-bottom: $spacing-03;
}
.buttons {
  display: flex;
  flex-wrap: wrap;
  gap: $spacing-03;
}
</style>
