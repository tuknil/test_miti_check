# Static UI served by nginx.
FROM artifact.it.att.com/docker-hub/nginx:alpine
COPY index.html app.js styles.css env.js.template /usr/share/nginx/html/
COPY default.conf /etc/nginx/conf.d/default.conf
COPY 40-mc-env.sh /docker-entrypoint.d/40-mc-env.sh
RUN chmod +x /docker-entrypoint.d/40-mc-env.sh
EXPOSE 80
