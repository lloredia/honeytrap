# ClickHouse plugin is installed at build time so the running container
# does not need outbound network access.
FROM grafana/grafana:11.4.0

USER root
RUN grafana cli --pluginsDir /usr/share/grafana/plugins plugins install grafana-clickhouse-datasource \
    && chown -R 472:472 /usr/share/grafana/plugins
USER 472
ENV GF_PATHS_PLUGINS=/usr/share/grafana/plugins
