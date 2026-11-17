#!/bin/bash

#
# Copyright (C) 2023 Nethesis S.r.l.
# SPDX-License-Identifier: GPL-3.0-or-later
#

# Terminate on error
set -e

# Prepare variables for later use
images=()
# The image will be pushed to GitHub container registry
repobase="${REPOBASE:-ghcr.io/geniusdynamics}"
# Configure the image name
reponame="kumomta"
# KumoMTA publishes dated stable releases (YYYY.MM.DD-<commit>), the same
# tags as its GitHub releases: no semver tag exists. renovate.json compares
# them with a regex versioning (date part only)
# renovate: datasource=docker packageName=ghcr.io/kumocorp/kumomta
KUMOMTA_VERSION=2026.09.29-b90d8bc1
# Node.js 25+ no longer ships Corepack, install it from npm
# renovate: datasource=npm packageName=corepack
corepack_version=0.36.0

# Create a new empty container image
container=$(buildah from scratch)

# Reuse existing nodebuilder-kumomta container, to speed up builds
if ! buildah containers --format "{{.ContainerName}}" | grep -q nodebuilder-kumomta; then
    echo "Pulling NodeJS runtime..."
    buildah from --name nodebuilder-kumomta -v "${PWD}:/usr/src:Z" docker.io/library/node:26.13.0-slim
    buildah run nodebuilder-kumomta sh -c "npm install -g corepack@${corepack_version} && corepack enable"
fi

echo "Build static UI files with node..."
buildah run \
    --workingdir=/usr/src/ui \
    --env="NODE_OPTIONS=--openssl-legacy-provider" \
    nodebuilder-kumomta \
    sh -c "yarn install && yarn build"

# Add imageroot directory to the container image
buildah add "${container}" imageroot /imageroot
buildah add "${container}" ui/dist /ui
# - rootless: kumod binds the SMTP ports with the host network (NS8 sets
#   net.ipv4.ip_unprivileged_port_start=23), like ns8-mail
# - two TCP ports on 127.0.0.1: the KumoMTA HTTP API, and the domain
#   management API of the integrations (kumomta-api)
# - a third TCP port for tsa-daemon (traffic shaping automation): on
#   127.0.0.1, or on the cluster VPN address when clustered
# - node:fwadm opens the SMTP ports, traefik@node:fulladm gives the TLS
#   certificate of the host name and the optional metrics route,
#   node:portsadm allocates the tsa-daemon port of an upgraded install
# - multi-node cluster (docs/cluster.md): kumomta@any:clusterpeer lets the
#   instances copy each other's cluster settings (reveal-cluster-settings),
#   valkey@any:valkeyclient gets client credentials from ns8-valkey
#   (grant-client)
buildah config --entrypoint=/ \
    --label="org.nethserver.authorizations=traefik@node:fulladm node:fwadm,portsadm kumomta@any:clusterpeer valkey@any:valkeyclient" \
    --label="org.nethserver.tcp-ports-demand=3" \
    --label="org.nethserver.rootfull=0" \
    --label="org.nethserver.min-core=3.20.1" \
    --label="org.nethserver.volumes=kumomta-spool" \
    --label="org.nethserver.images=ghcr.io/kumocorp/kumomta:${KUMOMTA_VERSION}" \
    "${container}"
# Commit the image
buildah commit "${container}" "${repobase}/${reponame}"

# Append the image URL to the images array
images+=("${repobase}/${reponame}")

#
# NOTICE:
#
# It is possible to build and publish multiple images.
#
# 1. create another buildah container
# 2. add things to it and commit it
# 3. append the image url to the images array
#

#
# Setup CI when pushing to Github. 
# Warning! docker::// protocol expects lowercase letters (,,)
if [[ -n "${CI}" ]]; then
    # Set output value for Github Actions
    printf "images=%s\n" "${images[*],,}" >> "${GITHUB_OUTPUT}"
else
    # Just print info for manual push
    printf "Publish the images with:\n\n"
    for image in "${images[@],,}"; do printf "  buildah push %s docker://%s:%s\n" "${image}" "${image}" "${IMAGETAG:-latest}" ; done
    printf "\n"
fi
