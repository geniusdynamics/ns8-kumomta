<!--
  Copyright (C) 2026 Genius Dynamics
  SPDX-License-Identifier: GPL-3.0-or-later
-->
<template>
  <cv-grid fullWidth>
    <cv-row>
      <cv-column class="page-title">
        <h2>{{ $t("domains.title") }}</h2>
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
    <!-- sending domains and DKIM -->
    <cv-row>
      <cv-column>
        <cv-tile light>
          <h4 class="mg-bottom">{{ $t("domains.sending_domains") }}</h4>
          <p class="mg-bottom">{{ $t("domains.sending_description") }}</p>
          <NsInlineNotification
            v-if="vault_enabled"
            kind="info"
            :title="$t('domains.dkim_in_openbao')"
            :description="$t('domains.dkim_in_openbao_description')"
            :showCloseButton="false"
          />
          <cv-skeleton-text
            v-if="loading.getConfiguration"
            :paragraph="true"
            :line-count="4"
          />
          <template v-else>
            <NsEmptyState
              v-if="!domains.length"
              :title="$t('domains.no_domains')"
            />
            <div v-for="(dom, index) in domains" :key="dom.key" class="item">
              <div class="row-fields">
                <NsTextInput
                  :label="$t('domains.domain')"
                  v-model.trim="dom.domain"
                  :disabled="busy || !dom.isNew"
                  placeholder="example.org"
                />
                <NsTextInput
                  :label="$t('domains.selector')"
                  v-model.trim="dom.selector"
                  :disabled="busy || !dom.isNew"
                  placeholder="kumo1"
                />
                <NsButton
                  kind="ghost"
                  :icon="TrashCan20"
                  :disabled="busy"
                  @click="domains.splice(index, 1)"
                  >{{ $t("common.remove") }}</NsButton
                >
              </div>
              <template v-if="!dom.isNew">
                <div class="mg-bottom-sm">
                  <NsTag
                    :kind="dom.key_location === 'missing' ? 'red' : 'green'"
                    :label="$t('domains.key_' + dom.key_location)"
                  />
                </div>
                <template v-if="dom.dkim_record">
                  <div class="label">{{ $t("domains.dns_record") }}</div>
                  <NsCodeSnippet
                    :copyTooltip="$t('common.copy_to_clipboard')"
                    :copyFeedback="$t('common.copied')"
                    :moreText="$t('common.show_more')"
                    :lessText="$t('common.show_less')"
                    light
                    class="mg-bottom-sm"
                    >{{ dom.dkim_record.name }} IN TXT "{{
                      dom.dkim_record.value
                    }}"</NsCodeSnippet
                  >
                </template>
                <NsButton
                  kind="tertiary"
                  size="small"
                  :icon="Restart20"
                  :loading="loading.generate === dom.domain"
                  :disabled="busy || !!loading.generate"
                  @click="generateKey(dom, dom.key_location !== 'missing')"
                  >{{
                    dom.key_location === "missing"
                      ? $t("domains.generate_key")
                      : dom.key_location === "local_not_in_openbao"
                      ? $t("domains.move_to_openbao")
                      : $t("domains.rotate_key")
                  }}</NsButton
                >
              </template>
            </div>
            <NsButton
              kind="secondary"
              :icon="Add20"
              class="mg-bottom"
              :disabled="busy"
              @click="addDomain"
              >{{ $t("domains.add_domain") }}</NsButton
            >
            <NsInlineNotification
              v-if="error.generate"
              kind="error"
              :title="$t('action.generate-dkim-key')"
              :description="error.generate"
              :showCloseButton="false"
            />
          </template>
        </cv-tile>
      </cv-column>
    </cv-row>
    <!-- inbound routes -->
    <cv-row>
      <cv-column>
        <cv-tile light>
          <h4 class="mg-bottom">{{ $t("domains.inbound_routes") }}</h4>
          <p class="mg-bottom">{{ $t("domains.inbound_description") }}</p>
          <NsEmptyState
            v-if="!routes.length && !loading.getConfiguration"
            :title="$t('domains.no_routes')"
          />
          <div
            v-for="(route, index) in routes"
            :key="route.key"
            class="row-fields"
          >
            <NsTextInput
              :label="$t('domains.domain')"
              v-model.trim="route.domain"
              :disabled="busy"
              placeholder="example.org"
            />
            <NsTextInput
              :label="$t('domains.route_host')"
              v-model.trim="route.host"
              :disabled="busy"
              placeholder="10.5.4.1"
            />
            <NsTextInput
              type="number"
              :label="$t('domains.route_port')"
              v-model.number="route.port"
              :disabled="busy"
              class="port"
            />
            <NsButton
              kind="ghost"
              :icon="TrashCan20"
              :disabled="busy"
              @click="routes.splice(index, 1)"
              >{{ $t("common.remove") }}</NsButton
            >
          </div>
          <NsButton
            kind="secondary"
            :icon="Add20"
            class="mg-bottom"
            :disabled="busy"
            @click="addRoute"
            >{{ $t("domains.add_route") }}</NsButton
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
  name: "Domains",
  mixins: [
    TaskService,
    IconService,
    UtilService,
    QueryParamService,
    PageTitleService,
    ModuleTask,
  ],
  pageTitle() {
    return this.$t("domains.title") + " - " + this.appName;
  },
  data() {
    return {
      q: { page: "domains" },
      urlCheckInterval: null,
      domains: [],
      routes: [],
      vault_enabled: false,
      loading: {
        getConfiguration: false,
        configureModule: false,
        generate: "",
      },
      error: {
        getConfiguration: "",
        configureModule: "",
        generate: "",
        domains: "",
        inbound_routes: "",
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
        this.vault_enabled = c.vault_enabled;
        this.domains = c.domains.map((d) =>
          Object.assign({ key: this.getUuid(), isNew: false }, d)
        );
        this.routes = c.inbound_routes.map((r) =>
          Object.assign({ key: this.getUuid() }, r)
        );
      } catch (failure) {
        this.error.getConfiguration = this.taskErrorMessage(failure);
      }
      this.loading.getConfiguration = false;
    },
    addDomain() {
      this.domains.push({
        key: this.getUuid(),
        domain: "",
        selector: "kumo1",
        isNew: true,
      });
    },
    addRoute() {
      this.routes.push({ key: this.getUuid(), domain: "", host: "", port: 25 });
    },
    async save() {
      this.clearErrors(this);
      this.loading.configureModule = true;
      const data = {
        domains: this.domains
          .filter((d) => d.domain)
          .map((d) => ({ domain: d.domain, selector: d.selector || "kumo1" })),
        inbound_routes: this.routes
          .filter((r) => r.domain && r.host)
          .map((r) => ({
            domain: r.domain,
            host: r.host,
            port: parseInt(r.port) || 25,
          })),
      };
      try {
        await this.runModuleTask("configure-module", data, {
          title: this.$t("domains.saving"),
          hidden: false,
        });
        this.getConfiguration();
      } catch (failure) {
        this.error.configureModule = this.taskErrorMessage(failure);
      }
      this.loading.configureModule = false;
    },
    async generateKey(dom, existing) {
      if (
        existing &&
        dom.key_location !== "local_not_in_openbao" &&
        !window.confirm(this.$t("domains.rotate_confirm"))
      ) {
        return;
      }
      this.error.generate = "";
      this.loading.generate = dom.domain;
      try {
        await this.runModuleTask(
          "generate-dkim-key",
          {
            domain: dom.domain,
            rotate: existing && dom.key_location !== "local_not_in_openbao",
          },
          { title: this.$t("action.generate-dkim-key"), hidden: false }
        );
        this.getConfiguration();
      } catch (failure) {
        this.error.generate = this.taskErrorMessage(failure);
      }
      this.loading.generate = "";
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
  max-width: 60rem;
}
.port {
  max-width: 8rem;
}
.label {
  font-size: 0.75rem;
  margin-bottom: $spacing-02;
}
</style>
