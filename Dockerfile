# SPDX-FileCopyrightText: 2022-present Intel Corporation
# SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
#
# SPDX-License-Identifier: Apache-2.0
#

FROM golang:1.21.5-bookworm AS builder

LABEL maintainer="ONF <omec-dev@opennetworking.org>"

RUN echo "deb http://archive.debian.org/debian stretch main" > /etc/apt/sources.list
RUN apt-get update && apt-get -y install apt-transport-https ca-certificates
RUN apt-get update
RUN apt-get -y install gcc cmake autoconf libtool pkg-config libmnl-dev libyaml-dev
RUN apt-get clean


RUN cd $GOPATH/src && mkdir -p smf
COPY . $GOPATH/src/smf
RUN cd $GOPATH/src/smf \
    && make all
# compile upf-adapter binary
RUN cd $GOPATH/src/smf/upfadapter && CGO_ENABLED=0 go build

FROM alpine:3.19 as smf

LABEL description="ONF open source 5G Core Network" \
    version="Stage 3"

ARG DEBUG_TOOLS

# Install debug tools ~ 100MB (if DEBUG_TOOLS is set to true)
RUN apk update && apk add -U vim strace net-tools curl netcat-openbsd bind-tools bash tcpdump

# Set working dir
WORKDIR /free5gc
RUN mkdir -p smf/
RUN mkdir -p bin/

# Copy executable and default certs
COPY --from=builder /go/src/smf/bin/* ./smf

# copy upf-adapter image
COPY --from=builder /go/src/smf/upfadapter/upf-adapter ./bin

WORKDIR /free5gc/smf
