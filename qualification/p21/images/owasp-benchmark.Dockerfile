ARG MAVEN_IMAGE=maven@sha256:e4a7ace3dc0d645ed97f8d9ad0b0d3f0b14fa8d150138f27f116d7105a639b82
ARG TOMCAT_IMAGE=tomcat@sha256:fcf35a12fc228567f91484b076f40d3d6528c15beb7e24f13ade176bf4b6b2ca

FROM ${MAVEN_IMAGE} AS build
WORKDIR /src
COPY . .
RUN mvn --batch-mode --no-transfer-progress -DskipTests clean package

FROM ${TOMCAT_IMAGE}
RUN rm -rf /usr/local/tomcat/webapps/* \
    && groupadd --gid 10001 p21 \
    && useradd --uid 10001 --gid 10001 --home-dir /nonexistent --shell /usr/sbin/nologin p21 \
    && mkdir -p /usr/local/tomcat/logs /usr/local/tomcat/temp /usr/local/tomcat/work \
    && chown -R 10001:10001 /usr/local/tomcat
COPY --from=build --chown=10001:10001 /src/target/*.war /usr/local/tomcat/webapps/ROOT.war
USER 10001:10001
EXPOSE 8080
CMD ["catalina.sh", "run"]
