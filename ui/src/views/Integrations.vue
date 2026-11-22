<!--
  Copyright (C) 2026 Genius Dynamics
  SPDX-License-Identifier: GPL-3.0-or-later
-->
<template>
  <cv-grid fullWidth>
    <cv-row>
      <cv-column class="page-title">
        <h2>{{ $t("integrations.title") }}</h2>
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
    <!-- HTTPS API -->
    <cv-row>
      <cv-column>
        <cv-tile light>
          <h4 class="mg-bottom">{{ $t("integrations.api") }}</h4>
          <p class="mg-bottom">{{ $t("integrations.api_description") }}</p>
          <NsTextInput
            :label="$t('integrations.api_host')"
            placeholder="mta-api.example.org"
            v-model.trim="api_host"
            :helper-text="$t('integrations.api_host_helper')"
            :invalid-message="error.api_host"
            :disabled="busy"
            ref="api_host"
            class="mg-bottom maxwidth"
          />
          <cv-text-area
            v-if="api_host"
            :label="$t('integrations.api_allowlist')"
            v-model="apiAllowlistText"
            :helper-text="$t('integrations.api_allowlist_helper')"
            :invalid-message="error.api_allowlist"
            :disabled="busy"
            ref="api_allowlist"
            class="mg-bottom maxwidth"
          />
          <template v-if="api_endpoints.inject">
            <div class="label">{{ $t("integrations.endpoints") }}</div>
            <NsCodeSnippet
              :copyTooltip="$t('common.copy_to_clipboard')"
              :copyFeedback="$t('common.copied')"
              :moreText="$t('common.show_more')"
              :lessText="$t('common.show_less')"
              light
              class="mg-bottom maxwidth"
              >{{ api_endpoints.inject }}
              {{ api_endpoints.domains }}</NsCodeSnippet
            >
          </template>
          <h4 class="mg-bottom">{{ $t("integrations.domain_policy") }}</h4>
          <NsToggle
            value="requireVerified"
            :label="$t('integrations.require_verified_domains')"
            v-model="require_verified_domains"
            :disabled="busy"
            class="mg-bottom"
          >
            <template #tooltip>
              {{ $t("integrations.require_verified_domains_tooltip") }}
            </template>
            <template slot="text-left">{{ $t("common.disabled") }}</template>
            <template slot="text-right">{{ $t("common.enabled") }}</template>
          </NsToggle>
          <NsTextInput
            :label="$t('integrations.spf_include')"
            :placeholder="'a:' + (hostname || 'mx.example.org')"
            v-model.trim="spf_include"
            :helper-text="$t('integrations.spf_include_helper')"
            :invalid-message="error.spf_include"
            :disabled="busy"
            ref="spf_include"
            class="mg-bottom maxwidth"
          />
          <NsTextInput
            :label="$t('integrations.bounce_domain')"
            placeholder="bounces.mx.example.org"
            v-model.trim="bounce_domain"
            :helper-text="$t('integrations.bounce_domain_helper')"
            :invalid-message="error.bounce_domain"
            :disabled="busy"
            ref="bounce_domain"
            class="mg-bottom maxwidth"
          />
        </cv-tile>
      </cv-column>
    </cv-row>
    <!-- credentials -->
    <cv-row>
      <cv-column>
        <cv-tile light>
          <h4 class="mg-bottom">{{ $t("integrations.credentials") }}</h4>
          <p class="mg-bottom">
            {{ $t("integrations.credentials_description") }}
          </p>
          <NsEmptyState
            v-if="!integrations.length && !loading.getConfiguration"
            :title="$t('integrations.no_integrations')"
          />
          <div
            v-for="(integ, index) in integrations"
            :key="integ.key"
            class="item"
          >
            <div class="row-fields">
              <NsTextInput
                :label="$t('integrations.name')"
                v-model.trim="integ.name"
                :disabled="busy || !integ.isNew"
                placeholder="platform1"
              />
              <NsTextInput
                :label="$t('integrations.tenant')"
                v-model.trim="integ.tenant"
                :helper-text="$t('integrations.tenant_helper')"
                :disabled="busy"
              />
              <NsTextInput
                v-if="!integ.tenant"
                :label="$t('integrations.tenant_prefix')"
                v-model.trim="integ.tenant_prefix"
                :helper-text="$t('integrations.tenant_prefix_helper')"
                placeholder="platform1-"
                :disabled="busy"
              />
              <NsTextInput
                :label="$t('integrations.max_message_rate')"
                v-model.trim="integ.max_message_rate"
                :helper-text="
                  integ.tenant
                    ? $t('integrations.max_message_rate_fixed_helper')
                    : $t('integrations.max_message_rate_multi_helper')
                "
                placeholder="1000/h"
                :disabled="busy"
                class="rate"
              />
              <NsTextInput
                :label="$t('integrations.max_domains')"
                v-model.number="integ.max_domains"
                type="number"
                min="0"
                :helper-text="
                  $t('integrations.max_domains_helper', {
                    count: integ.domains_count,
                  })
                "
                :disabled="busy"
                class="rate"
              />
              <NsButton
                kind="ghost"
                :icon="TrashCan20"
                :disabled="busy"
                @click="integrations.splice(index, 1)"
                >{{ $t("common.remove") }}</NsButton
              >
            </div>
            <div class="scopes mg-bottom-sm">
              <NsCheckbox
                v-for="scope in scopes"
                :key="scope"
                :label="$t('integrations.scope_' + scope)"
                :value="scope"
                v-model="integ.scopes"
                :disabled="busy"
              />
            </div>
            <div class="row-fields">
              <NsTextInput
                type="password"
                autocomplete="new-password"
                :label="$t('integrations.password')"
                v-model="integ.password"
                :placeholder="integ.password_set ? $t('common.unchanged') : ''"
                :helper-text="$t('integrations.password_helper')"
                :disabled="busy"
              />
              <NsButton
                kind="tertiary"
                size="small"
                :icon="Password20"
                :disabled="busy"
                @click="generatePassword(integ)"
                >{{ $t("integrations.generate_password") }}</NsButton
              >
            </div>
            <NsInlineNotification
              v-if="integ.generated"
              kind="info"
              :title="$t('integrations.copy_password_now')"
              :description="$t('integrations.copy_password_now_description')"
              :showCloseButton="false"
            />
            <NsCodeSnippet
              v-if="integ.generated"
              :copyTooltip="$t('common.copy_to_clipboard')"
              :copyFeedback="$t('common.copied')"
              :moreText="$t('common.show_more')"
              :lessText="$t('common.show_less')"
              light
              class="mg-bottom-sm"
              >{{ integ.password }}</NsCodeSnippet
            >
          </div>
          <NsButton
            kind="secondary"
            :icon="Add20"
            class="mg-bottom"
            :disabled="busy"
            @click="addIntegration"
            >{{ $t("integrations.add_integration") }}</NsButton
          >
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
  name: "Integrations",
  mixins: [
    TaskService,
    IconService,
    UtilService,
    QueryParamService,
    PageTitleService,
    ModuleTask,
  ],
  pageTitle() {
    return this.$t("integrations.title") + " - " + this.appName;
  },
  data() {
    return {
      q: { page: "integrations" },
      urlCheckInterval: null,
      scopes: ["inject", "smtp", "domains"],
      hostname: "",
      api_host: "",
      apiAllowlistText: "",
      api_endpoints: {},
      require_verified_domains: true,
      spf_include: "",
      bounce_domain: "",
      integrations: [],
      loading: { getConfiguration: false, configureModule: false },
      error: {
        getConfiguration: "",
        configureModule: "",
        api_host: "",
        api_allowlist: "",
        spf_include: "",
        bounce_domain: "",
        integrations: "",
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
        this.api_host = c.api_host;
        this.apiAllowlistText = c.api_allowlist.join("\n");
        this.api_endpoints = c.api_endpoints || {};
        this.require_verified_domains = c.require_verified_domains;
        this.spf_include = c.spf_include;
        this.bounce_domain = c.bounce_domain;
        this.integrations = c.integrations.map((i) =>
          Object.assign(
            {
              key: this.getUuid(),
              isNew: false,
              password: "",
              generated: false,
            },
            i,
            { scopes: [...i.scopes] }
          )
        );
      } catch (failure) {
        this.error.getConfiguration = this.taskErrorMessage(failure);
      }
      this.loading.getConfiguration = false;
    },
    addIntegration() {
      this.integrations.push({
        key: this.getUuid(),
        isNew: true,
        name: "",
        tenant: "",
        tenant_prefix: "",
        scopes: ["inject", "domains"],
        max_message_rate: "",
        max_domains: 0,
        domains_count: 0,
        password: "",
        password_set: false,
        generated: false,
      });
    },
    generatePassword(integ) {
      // Generated in the browser: the module stores only a salted hash
      const alphabet =
        "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
      const bytes = new Uint32Array(32);
      window.crypto.getRandomValues(bytes);
      integ.password = Array.from(bytes)
        .map((b) => alphabet[b % alphabet.length])
        .join("");
      integ.generated = true;
    },
    async save() {
      this.clearErrors(this);
      this.loading.configureModule = true;
      const data = {
        api_host: this.api_host,
        api_allowlist: this.linesToList(this.apiAllowlistText),
        require_verified_domains: this.require_verified_domains,
        spf_include: this.spf_include,
        bounce_domain: this.bounce_domain,
        integrations: this.integrations
          .filter((i) => i.name)
          .map((i) => {
            const out = {
              name: i.name,
              tenant: i.tenant || "",
              tenant_prefix: i.tenant ? "" : i.tenant_prefix || "",
              scopes: i.scopes,
              max_message_rate: i.max_message_rate || "",
              max_domains: Math.max(0, parseInt(i.max_domains, 10) || 0),
            };
            if (i.password) {
              out.password = i.password;
            }
            return out;
          }),
      };
      try {
        await this.runModuleTask("configure-module", data, {
          title: this.$t("integrations.saving"),
          hidden: false,
        });
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
.mg-bottom-sm {
  margin-bottom: $spacing-03;
}
.maxwidth {
  max-width: 38rem;
}
.item {
  border-bottom: 1px solid $ui-03;
  padding-bottom: $spacing-05;
  margin-bottom: $spacing-05;
  max-width: 60rem;
}
.row-fields {
  display: flex;
  gap: $spacing-05;
  align-items: flex-end;
  margin-bottom: $spacing-05;
}
.scopes {
  display: flex;
  gap: $spacing-06;
}
.rate {
  max-width: 10rem;
}
.label {
  font-size: 0.75rem;
  margin-bottom: $spacing-02;
}
</style>
