# SPDX-FileCopyrightText: 2022-present Intel Corporation
#
# SPDX-License-Identifier: Apache-2.0
#

FROM golang:alpine AS builder

LABEL maintainer="ankur.upadhyaya@intel.com"

WORKDIR /app

COPY go.mod .

COPY go.sum .

RUN go mod download

COPY . .

RUN go build

FROM alpine

WORKDIR /bin

COPY --from=builder /app/upf-adapter /bin/

CMD ["./upf-adapter"]
