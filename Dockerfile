FROM node:22-alpine AS build
WORKDIR /app
RUN corepack enable
COPY package.json pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile
COPY tsconfig.json tsconfig.build.json ./
COPY src ./src
RUN pnpm build && pnpm prune --prod

FROM node:22-alpine
WORKDIR /data
COPY --from=build /app/node_modules /app/node_modules
COPY --from=build /app/dist /app/dist
COPY assets /app/assets
COPY ui /app/ui
COPY --from=build /app/package.json /app/package.json
# Mount a directory holding watchtower.yaml and .env at /data; state is written to /data/.watchtower.
# The dashboard listens on 0.0.0.0:4545 and needs WATCHTOWER_PASSWORD or WATCHTOWER_READONLY=true.
ENV HOST=0.0.0.0 PORT=4545
EXPOSE 4545
ENTRYPOINT ["node", "/app/dist/cli.js"]
CMD ["serve"]
