# SPDX-FileCopyrightText: 2022-present Intel Corporation
#
# SPDX-License-Identifier: Apache-2.0
#

FROM golang:1.21.6-bookworm AS builder

WORKDIR /app

COPY . .

RUN CGO_ENABLED=0 go build

FROM alpine:3.19 as upf-adapter

ARG DEBUG_TOOLS

# Install debug tools ~ 50MB (if DEBUG_TOOLS is set to true)
RUN if [ "$DEBUG_TOOLS" = "true" ]; then \
        apk update && apk add -U vim strace net-tools curl netcat-openbsd bind-tools bash; \
        fi

WORKDIR /bin

COPY --from=builder /app/upf-adapter .

CMD ["./upf-adapter"]
