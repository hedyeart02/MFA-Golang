FROM nginx:1.27-alpine

COPY nginx.conf /etc/nginx/nginx.conf

EXPOSE 80 443

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:80/health || exit 1

CMD ["nginx", "-g", "daemon off;"]
