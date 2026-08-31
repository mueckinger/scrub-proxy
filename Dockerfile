FROM cgr.dev/chainguard/go AS build

WORKDIR /app
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags='-s -w' -o /bin/scrub-proxy .

FROM cgr.dev/chainguard/static
COPY --from=build /bin/scrub-proxy /usr/bin/
EXPOSE 8080
ENTRYPOINT ["/usr/bin/scrub-proxy"]
