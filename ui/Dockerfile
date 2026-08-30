# Static UI served by nginx.
FROM artifact.it.att.com/docker-hub/nginx:alpine
ENV GOPROXY=https://nm2553@att.com:cmVmdGtuOjAxOjE4MTg1MTYxOTE6WFg1VDFnd1Y5aDVYalFzT1lCbEs2ckQ4UmJa@artifact.it.att.com/artifactory/api/go/att-go-public-group
ENV GONOSUMDB=off
ENV GOPRIVATE=it.att.com
COPY index.html app.js styles.css env.js.template /usr/share/nginx/html/
COPY default.conf /etc/nginx/conf.d/default.conf
COPY 40-mc-env.sh /docker-entrypoint.d/40-mc-env.sh
RUN chmod +x /docker-entrypoint.d/40-mc-env.sh
EXPOSE 80
