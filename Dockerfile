FROM golang:1.23.0 AS builder
LABEL authors="lars.eppinger"

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

RUN mkdir src
COPY src/ ./src
RUN ls
RUN CGO_ENABLED=0 GOOS=linux go build ./src/graphql-iam.go


FROM alpine:latest

ARG USER=appuser
ARG GROUP=appusergroup
ENV HOME=/home/${USER}

RUN addgroup --system --gid 1001 ${GROUP} \
  && adduser --uid 1001 --system appuser --ingroup ${GROUP} --disabled-password --home ${HOME} --shell /bin/bash

USER ${USER}
WORKDIR ${HOME}

RUN mkdir -p resources/config
COPY --chown=${USER}:${GROUP} resources/config/config.yaml resources/config/
COPY --chown=${USER}:${GROUP} --from=builder /app/agent .

EXPOSE 8080

ENTRYPOINT ["sh", "-c", "./agent"]