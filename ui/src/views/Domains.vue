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
                  :disabled="busy || loading.remove === dom.domain"
                  :loading="loading.remove === dom.domain"
                  @click="removeDomain(dom, index)"
                  >{{ $t("common.remove") }}</NsButton
                >
              </div>
              <template v-if="!dom.isNew">
                <div class="mg-bottom-sm tags">
                  <NsTag
                    :kind="statusKind(dom.status)"
                    :label="$t('domains.status_' + dom.status)"
                  />
                  <NsTag
                    :kind="dom.key_location === 'missing' ? 'red' : 'green'"
                    :label="$t('domains.key_' + dom.key_location)"
                  />
                  <NsTag
                    v-if="dom.owner"
                    kind="purple"
                    :label="$t('domains.owner', { owner: dom.owner })"
                  />
                  <NsTag
                    v-if="dom.tenant"
                    kind="cool-gray"
                    :label="$t('domains.tenant', { tenant: dom.tenant })"
                  />
                  <span class="checked">{{
                    dom.last_checked
                      ? $t("domains.last_checked", { time: dom.last_checked })
                      : $t("domains.never_checked")
                  }}</span>
                </div>
                <div class="label">{{ $t("domains.dns_records") }}</div>
                <div
                  v-for="rec in dom.records"
                  :key="rec.check + rec.name"
                  class="record"
                >
                  <div class="record-head">
                    <NsTag
                      size="sm"
                      :kind="checkKind(dom, rec.check)"
                      :label="checkLabel(dom, rec)"
                    />
                    <span class="purpose">{{ rec.purpose }}</span>
                  </div>
                  <NsCodeSnippet
                    :copyTooltip="$t('common.copy_to_clipboard')"
                    :copyFeedback="$t('common.copied')"
                    :moreText="$t('common.show_more')"
                    :lessText="$t('common.show_less')"
                    light
                    class="mg-bottom-sm"
                    >{{ rec.name }} IN {{ rec.type }}
                    {{
                      rec.type === "TXT" ? '"' + rec.value + '"' : rec.value
                    }}</NsCodeSnippet
                  >
                </div>
                <NsButton
                  kind="tertiary"
                  size="small"
                  :icon="Search20"
                  :loading="loading.validate === dom.domain"
                  :disabled="busy || !!loading.validate"
                  class="mg-right"
                  @click="validateDomain(dom)"
                  >{{ $t("domains.validate") }}</NsButton
                >
                <template v-if="clustered && dom.key_location === 'missing'">
                  <NsButton
                    v-if="vault_enabled"
                    kind="tertiary"
                    size="small"
                    :icon="Locked20"
                    :loading="loading.generate === dom.domain"
                    :disabled="busy || !!loading.generate"
                    class="mg-right"
                    @click="installKey(dom, { source: 'shared' })"
                    >{{ $t("domains.use_shared_key") }}</NsButton
                  >
                  <NsButton
                    kind="tertiary"
                    size="small"
                    :icon="Download20"
                    :disabled="busy || !!loading.generate"
                    class="mg-right"
                    @click="openImport(dom)"
                    >{{ $t("domains.import_key") }}</NsButton
                  >
                </template>
                <NsButton
                  v-if="!clustered || dom.key_location !== 'openbao'"
                  kind="tertiary"
                  size="small"
                  :icon="Restart20"
                  :loading="loading.generate === dom.domain"
                  :disabled="
                    busy ||
                    !!loading.generate ||
                    (clustered &&
                      dom.key_location !== 'missing' &&
                      dom.key_location !== 'local_not_in_openbao')
                  "
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
              v-if="error.validate"
              kind="error"
              :title="$t('action.validate-domain')"
              :description="error.validate"
              :showCloseButton="false"
            />
            <NsInlineNotification
              v-if="clustered"
              kind="info"
              :title="$t('domains.cluster_keys_title')"
              :description="
                vault_enabled
                  ? $t('domains.cluster_keys_openbao')
                  : $t('domains.cluster_keys_local')
              "
              :showCloseButton="false"
            />
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
    <!-- cluster: import the key of a domain (PEM, or from a peer) -->
    <NsModal
      size="default"
      :visible="importModal.visible"
      :primaryButtonDisabled="
        loading.generate !== '' ||
        (importModal.mode === 'peer' ? !importModal.peer : !importModal.pem)
      "
      :isLoading="loading.generate !== ''"
      @modal-hidden="importModal.visible = false"
      @secondary-click="importModal.visible = false"
      @primary-click="importKey"
    >
      <template slot="title">{{
        $t("domains.import_title", { domain: importModal.domain })
      }}</template>
      <template slot="content">
        <cv-radio-group vertical class="mg-bottom">
          <cv-radio-button
            :label="$t('domains.import_from_peer')"
            value="peer"
            v-model="importModal.mode"
            :disabled="!peers.length"
          />
          <cv-radio-button
            :label="$t('domains.import_pem')"
            value="import"
            v-model="importModal.mode"
          />
        </cv-radio-group>
        <NsComboBox
          v-if="importModal.mode === 'peer'"
          v-model="importModal.peer"
          :options="peerOptions"
          :title="$t('domains.import_peer')"
          :label="$t('cluster.choose')"
          :auto-filter="true"
          :auto-highlight="true"
          class="mg-bottom"
        />
        <cv-text-area
          v-else
          :label="$t('domains.import_pem_label')"
          v-model="importModal.pem"
          :helper-text="$t('domains.import_pem_helper')"
          class="mg-bottom"
        />
        <NsInlineNotification
          v-if="error.generate"
          kind="error"
          :title="$t('action.generate-dkim-key')"
          :description="error.generate"
          :showCloseButton="false"
        />
      </template>
      <template slot="secondary-button">{{ $t("common.cancel") }}</template>
      <template slot="primary-button">{{ $t("domains.import_key") }}</template>
    </NsModal>
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
      // cluster: keys are imported from a peer or a PEM, never overwritten
      clustered: false,
      peers: [],
      importModal: {
        visible: false,
        domain: "",
        mode: "peer",
        peer: "",
        pem: "",
      },
      loading: {
        getConfiguration: false,
        configureModule: false,
        generate: "",
        validate: "",
        remove: "",
      },
      error: {
        getConfiguration: "",
        configureModule: "",
        generate: "",
        validate: "",
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
    peerOptions() {
      return this.peers.map((p) => ({
        name: p.module_id,
        value: p.module_id,
        label: `${p.ui_name || p.module_id} (${p.module_id})`,
      }));
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
        this.clustered = c.cluster_store !== "none";
        this.peers = (c.cluster_peers || []).filter((p) => p.same_store);
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
        // the domains of the integrations are managed through the API
        domains: this.domains
          .filter((d) => d.domain && !d.owner)
          .map((d) => ({
            domain: d.domain,
            selector: d.selector || "kumo1",
            tenant: d.tenant || "",
          })),
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
    statusKind(status) {
      return { verified: "green", failed: "red" }[status] || "warm-gray";
    },
    findCheck(dom, name) {
      return (dom.checks || []).find((c) => c.name === name);
    },
    checkKind(dom, name) {
      const check = this.findCheck(dom, name);
      if (!check) {
        return "warm-gray";
      }
      return { pass: "green", fail: "red" }[check.status] || "warm-gray";
    },
    checkLabel(dom, rec) {
      const check = this.findCheck(dom, rec.check);
      const state = check ? check.status : "unchecked";
      return (
        this.$t("domains.check_" + rec.check) +
        (rec.required ? "" : " (" + this.$t("domains.recommended") + ")") +
        ": " +
        this.$t("domains.check_status_" + state)
      );
    },
    async validateDomain(dom) {
      this.error.validate = "";
      this.loading.validate = dom.domain;
      try {
        await this.runModuleTask(
          "validate-domain",
          { domain: dom.domain },
          { title: this.$t("action.validate-domain"), hidden: false }
        );
        this.getConfiguration();
      } catch (failure) {
        this.error.validate = this.taskErrorMessage(failure);
      }
      this.loading.validate = "";
    },
    async removeDomain(dom, index) {
      if (!dom.owner) {
        // administrator domains are saved with the page
        this.domains.splice(index, 1);
        return;
      }
      if (!window.confirm(this.$t("domains.remove_api_confirm", dom))) {
        return;
      }
      this.loading.remove = dom.domain;
      try {
        await this.runModuleTask(
          "remove-domain",
          { domain: dom.domain },
          { title: this.$t("action.remove-domain"), hidden: false }
        );
        this.getConfiguration();
      } catch (failure) {
        this.error.validate = this.taskErrorMessage(failure);
      }
      this.loading.remove = "";
    },
    openImport(dom) {
      this.error.generate = "";
      this.importModal = {
        visible: true,
        domain: dom.domain,
        mode: this.peers.length ? "peer" : "import",
        peer: this.peers.length ? this.peers[0].module_id : "",
        pem: "",
      };
    },
    async importKey() {
      const data =
        this.importModal.mode === "peer"
          ? { source: "peer", peer: this.importModal.peer }
          : { source: "import", private_key: this.importModal.pem };
      if (await this.installKey({ domain: this.importModal.domain }, data)) {
        this.importModal.visible = false;
        this.importModal.pem = "";
      }
    },
    async installKey(dom, data) {
      this.error.generate = "";
      this.loading.generate = dom.domain;
      let ok = false;
      try {
        await this.runModuleTask(
          "generate-dkim-key",
          Object.assign({ domain: dom.domain }, data),
          { title: this.$t("action.generate-dkim-key"), hidden: false }
        );
        ok = true;
        this.getConfiguration();
      } catch (failure) {
        this.error.generate = this.taskErrorMessage(failure);
      }
      this.loading.generate = "";
      return ok;
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
.tags {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: $spacing-02;
}
.checked {
  font-size: 0.75rem;
  color: $text-02;
  margin-left: $spacing-03;
}
.record-head {
  display: flex;
  align-items: center;
  gap: $spacing-03;
  margin-bottom: $spacing-02;
}
.purpose {
  font-size: 0.75rem;
  color: $text-02;
}
.mg-right {
  margin-right: $spacing-03;
}
.label {
  font-size: 0.75rem;
  margin-bottom: $spacing-02;
}
</style>
