<!--
  Copyright (C) 2026 Genius Dynamics
  SPDX-License-Identifier: GPL-3.0-or-later
-->
<template>
  <cv-grid fullWidth>
    <cv-row>
      <cv-column class="page-title">
        <h2>{{ $t("openbao.title") }}</h2>
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
          <p class="mg-bottom">{{ $t("openbao.description") }}</p>
          <cv-form @submit.prevent="save">
            <NsToggle
              value="vault"
              :label="$t('openbao.enabled')"
              v-model="vault_enabled"
              :disabled="busy"
              class="mg-bottom"
            >
              <template #tooltip>{{ $t("openbao.enabled_tooltip") }}</template>
              <template slot="text-left">{{ $t("common.disabled") }}</template>
              <template slot="text-right">{{ $t("common.enabled") }}</template>
            </NsToggle>
            <template v-if="vault_enabled">
              <div v-if="servers.length" class="mg-bottom maxwidth">
                <div class="label">{{ $t("openbao.discovered") }}</div>
                <div class="servers">
                  <NsButton
                    v-for="server in servers"
                    :key="server.module_id + server.url"
                    kind="tertiary"
                    size="small"
                    :disabled="busy"
                    @click="vault_address = server.url"
                    >{{ server.ui_name || server.module_id }} ({{
                      server.url
                    }})</NsButton
                  >
                </div>
              </div>
              <NsTextInput
                :label="$t('openbao.address')"
                v-model.trim="vault_address"
                placeholder="https://vault.example.org"
                :helper-text="$t('openbao.address_helper')"
                :invalid-message="error.vault_address"
                :disabled="busy"
                ref="vault_address"
                class="mg-bottom maxwidth"
              />
              <NsTextInput
                type="password"
                autocomplete="new-password"
                :label="$t('openbao.token')"
                v-model="vault_token"
                :placeholder="vault_token_set ? $t('common.unchanged') : ''"
                :helper-text="$t('openbao.token_helper')"
                :invalid-message="error.vault_token"
                :disabled="busy"
                ref="vault_token"
                class="mg-bottom maxwidth"
              />
              <NsTextInput
                :label="$t('openbao.mount')"
                v-model.trim="vault_mount"
                :invalid-message="error.vault_mount"
                :disabled="busy"
                ref="vault_mount"
                class="mg-bottom narrow"
              />
              <NsTextInput
                :label="$t('openbao.path')"
                v-model.trim="vault_path"
                :helper-text="$t('openbao.path_helper', { path: vault_path })"
                :invalid-message="error.vault_path"
                :disabled="busy"
                ref="vault_path"
                class="mg-bottom maxwidth"
              />
              <NsTextInput
                :label="$t('openbao.key')"
                v-model.trim="vault_key"
                placeholder="key"
                :helper-text="$t('openbao.key_helper')"
                :invalid-message="error.vault_key"
                :disabled="busy"
                ref="vault_key"
                class="mg-bottom narrow"
              />
            </template>
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
  name: "OpenBao",
  mixins: [
    TaskService,
    IconService,
    UtilService,
    QueryParamService,
    PageTitleService,
    ModuleTask,
  ],
  pageTitle() {
    return this.$t("openbao.title") + " - " + this.appName;
  },
  data() {
    return {
      q: { page: "openbao" },
      urlCheckInterval: null,
      vault_enabled: false,
      vault_address: "",
      vault_token: "",
      vault_token_set: false,
      vault_mount: "secret",
      vault_path: "kumomta",
      vault_key: "",
      servers: [],
      loading: { getConfiguration: false, configureModule: false },
      error: {
        getConfiguration: "",
        configureModule: "",
        vault_address: "",
        vault_token: "",
        vault_mount: "",
        vault_path: "",
        vault_key: "",
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
    this.listServers();
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
        this.vault_address = c.vault_address;
        this.vault_token_set = c.vault_token_set;
        this.vault_mount = c.vault_mount;
        this.vault_path = c.vault_path;
        this.vault_key = c.vault_key;
      } catch (failure) {
        this.error.getConfiguration = this.taskErrorMessage(failure);
      }
      this.loading.getConfiguration = false;
    },
    async listServers() {
      try {
        const out = await this.runModuleTask("list-openbao-servers");
        this.servers = out.servers;
        if (!this.vault_address && this.servers.length) {
          // Offer the first discovered instance as default
          this.vault_address = this.servers[0].url;
        }
      } catch (failure) {
        this.servers = [];
      }
    },
    async save() {
      this.clearErrors(this);
      if (this.vault_enabled && !this.vault_address) {
        this.error.vault_address = this.$t("common.required");
        this.focusElement("vault_address");
        return;
      }
      if (this.vault_enabled && !this.vault_token && !this.vault_token_set) {
        this.error.vault_token = this.$t("common.required");
        this.focusElement("vault_token");
        return;
      }
      const data = {
        vault_enabled: this.vault_enabled,
        vault_address: this.vault_address,
        vault_mount: this.vault_mount || "secret",
        vault_path: this.vault_path || "kumomta",
        vault_key: this.vault_key,
      };
      if (this.vault_token) {
        data.vault_token = this.vault_token;
      }
      this.loading.configureModule = true;
      try {
        await this.runModuleTask("configure-module", data, {
          title: this.$t("openbao.saving"),
          hidden: false,
        });
        this.vault_token = "";
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
.label {
  font-size: 0.75rem;
  margin-bottom: $spacing-03;
}
.servers {
  display: flex;
  flex-wrap: wrap;
  gap: $spacing-03;
}
</style>
