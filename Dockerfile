# SPDX-FileCopyrightText: 2022-present Intel Corporation
# SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
#
# SPDX-License-Identifier: Apache-2.0
#

FROM golang:1.23.1-bookworm AS builder

LABEL maintainer="Aether SD-Core <dev@lists.aetherproject.org>"

RUN apt-get update && \
    apt-get -y install --no-install-recommends \
    apt-transport-https \
    ca-certificates \
    gcc \
    cmake \
    autoconf \
    libtool \
    pkg-config \
    libmnl-dev \
    libyaml-dev && \
    apt-get clean

WORKDIR $GOPATH/src/smf
COPY . .
RUN make all

WORKDIR $GOPATH/src/smf/upfadapter
RUN CGO_ENABLED=0 go build

FROM alpine:3.20 AS smf

LABEL description="ONF open source 5G Core Network" \
    version="Stage 3"

ARG DEBUG_TOOLS

RUN apk update && apk add --no-cache -U bash

# Install debug tools ~ 50MB (if DEBUG_TOOLS is set to true)
RUN if [ "$DEBUG_TOOLS" = "true" ]; then \
        apk update && apk add --no-cache -U vim strace net-tools curl netcat-openbsd bind-tools tcpdump; \
        fi

# Set working dir
WORKDIR /free5gc/bin

# copy upf-adapter image
COPY --from=builder /go/src/smf/upfadapter/upf-adapter .

# Set working dir
WORKDIR /free5gc/smf

# Copy executable and default certs
COPY --from=builder /go/src/smf/bin/* .
