<!--
  Copyright (C) 2026 Genius Dynamics
  SPDX-License-Identifier: GPL-3.0-or-later
-->
<template>
  <cv-grid fullWidth>
    <cv-row>
      <cv-column class="page-title">
        <h2>{{ $t("users.title") }}</h2>
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
          <p class="mg-bottom">{{ $t("users.description") }}</p>
          <cv-skeleton-text
            v-if="loading.getConfiguration"
            :paragraph="true"
            :line-count="4"
          />
          <template v-else>
            <NsEmptyState v-if="!users.length" :title="$t('users.no_users')" />
            <div
              v-for="(user, index) in users"
              :key="user.key"
              class="row-fields"
            >
              <NsTextInput
                :label="$t('users.username')"
                v-model.trim="user.username"
                :disabled="loading.configureModule || !user.isNew"
                :ref="'username' + index"
              />
              <NsTextInput
                type="password"
                autocomplete="new-password"
                :label="$t('users.password')"
                v-model="user.password"
                :placeholder="user.isNew ? '' : $t('common.unchanged')"
                :disabled="loading.configureModule"
              />
              <NsButton
                kind="ghost"
                :icon="TrashCan20"
                :disabled="loading.configureModule"
                @click="users.splice(index, 1)"
                >{{ $t("common.remove") }}</NsButton
              >
            </div>
            <NsButton
              kind="secondary"
              :icon="Add20"
              class="mg-bottom"
              :disabled="loading.configureModule"
              @click="addUser"
              >{{ $t("users.add_user") }}</NsButton
            >
          </template>
          <NsInlineNotification
            v-if="error.smtp_users"
            kind="error"
            :title="$t('validation.validation_error')"
            :description="error.smtp_users"
            :showCloseButton="false"
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
            :disabled="loading.getConfiguration || loading.configureModule"
            @click="save"
            >{{ $t("common.save") }}</NsButton
          >
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
  name: "Users",
  mixins: [
    TaskService,
    IconService,
    UtilService,
    QueryParamService,
    PageTitleService,
    ModuleTask,
  ],
  pageTitle() {
    return this.$t("users.title") + " - " + this.appName;
  },
  data() {
    return {
      q: { page: "users" },
      urlCheckInterval: null,
      users: [],
      loading: { getConfiguration: false, configureModule: false },
      error: { getConfiguration: "", configureModule: "", smtp_users: "" },
    };
  },
  computed: {
    ...mapState(["instanceName", "core", "appName"]),
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
        this.users = c.smtp_users.map((u) => ({
          key: this.getUuid(),
          username: u.username,
          password: "",
          isNew: false,
        }));
      } catch (failure) {
        this.error.getConfiguration = this.taskErrorMessage(failure);
      }
      this.loading.getConfiguration = false;
    },
    addUser() {
      this.users.push({
        key: this.getUuid(),
        username: "",
        password: "",
        isNew: true,
      });
    },
    async save() {
      this.clearErrors(this);
      const smtp_users = [];
      for (const user of this.users) {
        if (!user.username) {
          continue;
        }
        const entry = { username: user.username };
        if (user.password) {
          entry.password = user.password;
        }
        smtp_users.push(entry);
      }
      this.loading.configureModule = true;
      try {
        await this.runModuleTask(
          "configure-module",
          { smtp_users },
          { title: this.$t("users.saving"), hidden: false }
        );
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
.row-fields {
  display: flex;
  gap: $spacing-05;
  align-items: flex-end;
  margin-bottom: $spacing-05;
  max-width: 50rem;
}
</style>
