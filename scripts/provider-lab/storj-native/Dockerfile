FROM postgres@sha256:194e55feb2597b1465dbee81cc9fd8d204566cd2eb42c8d22fd6c931a38781b1
COPY --chmod=0555 planet.test /opt/triage/planet.test
COPY --chmod=0555 rclone /opt/triage/rclone
COPY --chmod=0555 entrypoint.sh /opt/triage/run.sh
COPY resources /opt/triage/web
USER 999:999
ENTRYPOINT ["/opt/triage/run.sh"]
