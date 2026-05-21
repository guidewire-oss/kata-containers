#!/usr/bin/env bash
#
# Copyright (c) 2026
#
# SPDX-License-Identifier: Apache-2.0
#

MIGRATION_COORDINATOR_PATH="protocols/migration_coordinator"

# shellcheck disable=SC2154
protoc \
    -I="${GOPATH}/src" \
    --proto_path="${MIGRATION_COORDINATOR_PATH}" \
    --go_out="${MIGRATION_COORDINATOR_PATH}" \
    --go-grpc_out="${MIGRATION_COORDINATOR_PATH}" \
    "${MIGRATION_COORDINATOR_PATH}/migration_coordinator.proto"
