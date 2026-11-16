<!--
  Copyright (C) 2026 Genius Dynamics
  SPDX-License-Identifier: GPL-3.0-or-later
-->
<template>
  <cv-grid fullWidth>
    <cv-row>
      <cv-column class="page-title">
        <h2>{{ $t("delivery.title") }}</h2>
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
    <!-- smarthost -->
    <cv-row>
      <cv-column>
        <cv-tile light>
          <h4 class="mg-bottom">{{ $t("delivery.smarthost") }}</h4>
          <p class="mg-bottom">{{ $t("delivery.smarthost_description") }}</p>
          <NsToggle
            value="smarthost"
            :label="$t('delivery.smarthost_enabled')"
            v-model="smarthost_enabled"
            :disabled="busy"
            class="mg-bottom"
          >
            <template slot="text-left">{{ $t("common.disabled") }}</template>
            <template slot="text-right">{{ $t("common.enabled") }}</template>
          </NsToggle>
          <template v-if="smarthost_enabled">
            <div class="row-fields">
              <NsTextInput
                :label="$t('delivery.smarthost_host')"
                v-model.trim="smarthost_host"
                placeholder="smtp.example.net"
                :invalid-message="error.smarthost_host"
                :disabled="busy"
                ref="smarthost_host"
              />
              <NsTextInput
                type="number"
                :label="$t('delivery.smarthost_port')"
                v-model.number="smarthost_port"
                :disabled="busy"
                class="port"
              />
            </div>
            <NsComboBox
              :title="$t('delivery.smarthost_tls')"
              :label="$t('delivery.smarthost_tls')"
              v-model="smarthost_tls"
              :options="tlsOptions"
              :auto-filter="false"
              :auto-highlight="true"
              :disabled="busy"
              class="mg-bottom maxwidth"
            />
            <NsTextInput
              :label="$t('delivery.smarthost_username')"
              v-model.trim="smarthost_username"
              :helper-text="$t('delivery.smarthost_username_helper')"
              :disabled="busy"
              class="mg-bottom maxwidth"
            />
            <NsTextInput
              v-if="smarthost_username"
              type="password"
              autocomplete="new-password"
              :label="$t('delivery.smarthost_password')"
              v-model="smarthost_password"
              :placeholder="
                smarthost_password_set ? $t('common.unchanged') : ''
              "
              :helper-text="
                vault_enabled ? $t('delivery.secret_in_openbao') : ''
              "
              :invalid-message="error.smarthost_password"
              :disabled="busy"
              ref="smarthost_password"
              class="mg-bottom maxwidth"
            />
          </template>
        </cv-tile>
      </cv-column>
    </cv-row>
    <!-- shaping -->
    <cv-row>
      <cv-column>
        <cv-tile light>
          <h4 class="mg-bottom">{{ $t("delivery.shaping") }}</h4>
          <p class="mg-bottom">{{ $t("delivery.shaping_description") }}</p>
          <div
            v-for="(rule, index) in shaping"
            :key="rule.key"
            class="row-fields"
          >
            <NsTextInput
              :label="$t('delivery.destination')"
              v-model.trim="rule.domain"
              placeholder="gmail.com"
              :disabled="busy"
            />
            <NsTextInput
              type="number"
              :label="$t('delivery.connection_limit')"
              v-model.number="rule.connection_limit"
              :disabled="busy"
              class="port"
            />
            <NsTextInput
              :label="$t('delivery.max_message_rate')"
              v-model.trim="rule.max_message_rate"
              placeholder="100/min"
              :disabled="busy"
              class="rate"
            />
            <NsTextInput
              type="number"
              :label="$t('delivery.max_deliveries_per_connection')"
              v-model.number="rule.max_deliveries_per_connection"
              :disabled="busy"
              class="port"
            />
            <NsButton
              kind="ghost"
              :icon="TrashCan20"
              :disabled="busy"
              @click="shaping.splice(index, 1)"
              >{{ $t("common.remove") }}</NsButton
            >
          </div>
          <NsButton
            kind="secondary"
            :icon="Add20"
            :disabled="busy"
            @click="addRule"
            >{{ $t("delivery.add_rule") }}</NsButton
          >
        </cv-tile>
      </cv-column>
    </cv-row>
    <!-- webhook -->
    <cv-row>
      <cv-column>
        <cv-tile light>
          <h4 class="mg-bottom">{{ $t("delivery.webhook") }}</h4>
          <p class="mg-bottom">{{ $t("delivery.webhook_description") }}</p>
          <NsToggle
            value="webhook"
            :label="$t('delivery.webhook_enabled')"
            v-model="webhook_enabled"
            :disabled="busy"
            class="mg-bottom"
          >
            <template slot="text-left">{{ $t("common.disabled") }}</template>
            <template slot="text-right">{{ $t("common.enabled") }}</template>
          </NsToggle>
          <template v-if="webhook_enabled">
            <NsTextInput
              :label="$t('delivery.webhook_url')"
              v-model.trim="webhook_url"
              placeholder="https://logs.example.org/kumomta"
              :invalid-message="error.webhook_url"
              :disabled="busy"
              ref="webhook_url"
              class="mg-bottom maxwidth"
            />
            <NsTextInput
              type="password"
              autocomplete="new-password"
              :label="$t('delivery.webhook_token')"
              v-model="webhook_token"
              :placeholder="webhook_token_set ? $t('common.unchanged') : ''"
              :helper-text="
                vault_enabled
                  ? $t('delivery.secret_in_openbao')
                  : $t('delivery.webhook_token_helper')
              "
              :invalid-message="error.webhook_token"
              :disabled="busy"
              ref="webhook_token"
              class="mg-bottom maxwidth"
            />
            <NsCheckbox
              v-if="webhook_token_set"
              :label="$t('delivery.webhook_token_clear')"
              v-model="webhook_token_clear"
              value="clear"
              :disabled="busy"
              class="mg-bottom"
            />
            <NsTextInput
              type="password"
              autocomplete="new-password"
              :label="$t('delivery.webhook_signing_secret')"
              v-model="webhook_signing_secret"
              :placeholder="
                webhook_signing_secret_set ? $t('common.unchanged') : ''
              "
              :helper-text="$t('delivery.webhook_signing_secret_helper')"
              :invalid-message="error.webhook_signing_secret"
              :disabled="busy"
              ref="webhook_signing_secret"
              class="mg-bottom maxwidth"
            />
            <NsCheckbox
              v-if="webhook_signing_secret_set"
              :label="$t('delivery.webhook_signing_secret_clear')"
              v-model="webhook_signing_secret_clear"
              value="clearSigning"
              :disabled="busy"
              class="mg-bottom"
            />
            <div class="label">{{ $t("delivery.webhook_record_types") }}</div>
            <div class="checkboxes mg-bottom">
              <NsCheckbox
                v-for="rtype in recordTypes"
                :key="rtype"
                :label="rtype"
                :value="rtype"
                v-model="webhook_record_types"
                :disabled="busy"
              />
            </div>
          </template>
        </cv-tile>
      </cv-column>
    </cv-row>
    <cv-row>
      <cv-column>
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
          @click="save"
          >{{ $t("common.save") }}</NsButton
        >
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
  name: "Delivery",
  mixins: [
    TaskService,
    IconService,
    UtilService,
    QueryParamService,
    PageTitleService,
    ModuleTask,
  ],
  pageTitle() {
    return this.$t("delivery.title") + " - " + this.appName;
  },
  data() {
    return {
      q: { page: "delivery" },
      urlCheckInterval: null,
      vault_enabled: false,
      smarthost_enabled: false,
      smarthost_host: "",
      smarthost_port: 587,
      smarthost_tls: "required",
      smarthost_username: "",
      smarthost_password: "",
      smarthost_password_set: false,
      shaping: [],
      webhook_enabled: false,
      webhook_url: "",
      webhook_token: "",
      webhook_token_set: false,
      webhook_token_clear: false,
      webhook_signing_secret: "",
      webhook_signing_secret_set: false,
      webhook_signing_secret_clear: false,
      webhook_record_types: [],
      recordTypes: [
        "Reception",
        "Delivery",
        "Bounce",
        "TransientFailure",
        "Expiration",
        "AdminBounce",
        "OOB",
        "Feedback",
        "Rejection",
      ],
      loading: { getConfiguration: false, configureModule: false },
      error: {
        getConfiguration: "",
        configureModule: "",
        smarthost_host: "",
        smarthost_password: "",
        webhook_url: "",
        webhook_token: "",
        webhook_signing_secret: "",
        shaping: "",
      },
    };
  },
  computed: {
    ...mapState(["instanceName", "core", "appName"]),
    busy() {
      return this.loading.getConfiguration || this.loading.configureModule;
    },
    tlsOptions() {
      return ["required", "required_insecure", "opportunistic", "disabled"].map(
        (v) => ({ name: v, value: v, label: this.$t("delivery.tls_" + v) })
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
    async getConfiguration() {
      this.loading.getConfiguration = true;
      this.error.getConfiguration = "";
      try {
        const c = await this.runModuleTask("get-configuration");
        this.vault_enabled = c.vault_enabled;
        this.smarthost_enabled = c.smarthost_enabled;
        this.smarthost_host = c.smarthost_host;
        this.smarthost_port = c.smarthost_port;
        this.smarthost_tls = c.smarthost_tls;
        this.smarthost_username = c.smarthost_username;
        this.smarthost_password_set = c.smarthost_password_set;
        this.shaping = c.shaping.map((r) =>
          Object.assign({ key: this.getUuid() }, r)
        );
        this.webhook_enabled = c.webhook_enabled;
        this.webhook_url = c.webhook_url;
        this.webhook_token_set = c.webhook_token_set;
        this.webhook_token_clear = false;
        this.webhook_signing_secret_set = c.webhook_signing_secret_set;
        this.webhook_signing_secret_clear = false;
        this.webhook_record_types = c.webhook_record_types;
      } catch (failure) {
        this.error.getConfiguration = this.taskErrorMessage(failure);
      }
      this.loading.getConfiguration = false;
    },
    addRule() {
      this.shaping.push({
        key: this.getUuid(),
        domain: "",
        connection_limit: 5,
        max_message_rate: "",
        max_deliveries_per_connection: 50,
      });
    },
    async save() {
      this.clearErrors(this);
      const data = {
        smarthost_enabled: this.smarthost_enabled,
        smarthost_host: this.smarthost_host,
        smarthost_port: parseInt(this.smarthost_port) || 587,
        smarthost_tls: this.smarthost_tls,
        smarthost_username: this.smarthost_username,
        shaping: this.shaping
          .filter((r) => r.domain)
          .map((r) => {
            const rule = { domain: r.domain };
            if (r.connection_limit) {
              rule.connection_limit = parseInt(r.connection_limit);
            }
            if (r.max_message_rate) {
              rule.max_message_rate = r.max_message_rate;
            }
            if (r.max_deliveries_per_connection) {
              rule.max_deliveries_per_connection = parseInt(
                r.max_deliveries_per_connection
              );
            }
            return rule;
          }),
        webhook_enabled: this.webhook_enabled,
        webhook_url: this.webhook_url,
        webhook_record_types: this.webhook_record_types,
      };
      if (this.smarthost_password) {
        data.smarthost_password = this.smarthost_password;
      }
      if (this.webhook_token) {
        data.webhook_token = this.webhook_token;
      }
      if (this.webhook_signing_secret) {
        data.webhook_signing_secret = this.webhook_signing_secret;
      }
      if (this.webhook_signing_secret_clear) {
        data.webhook_signing_secret_clear = true;
      }
      if (this.webhook_token_clear) {
        data.webhook_token_clear = true;
      }
      this.loading.configureModule = true;
      try {
        await this.runModuleTask("configure-module", data, {
          title: this.$t("delivery.saving"),
          hidden: false,
        });
        this.smarthost_password = "";
        this.webhook_token = "";
        this.webhook_signing_secret = "";
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
.row-fields {
  display: flex;
  flex-wrap: wrap;
  gap: $spacing-05;
  align-items: flex-end;
  margin-bottom: $spacing-05;
  max-width: 70rem;
}
.port {
  max-width: 10rem;
}
.rate {
  max-width: 12rem;
}
.label {
  font-size: 0.75rem;
  margin-bottom: $spacing-03;
}
.checkboxes {
  display: flex;
  flex-wrap: wrap;
  gap: $spacing-05;
}
</style>
