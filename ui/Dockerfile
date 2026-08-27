# Static UI served by nginx. The API endpoint is injected at runtime from the
# API_BASE env var (rendered into env.js by 40-mc-env.sh at container start).
FROM nginx:alpine
COPY index.html app.js styles.css env.js.template /usr/share/nginx/html/
COPY default.conf /etc/nginx/conf.d/default.conf
COPY 40-mc-env.sh /docker-entrypoint.d/40-mc-env.sh
RUN chmod +x /docker-entrypoint.d/40-mc-env.sh
EXPOSE 80
