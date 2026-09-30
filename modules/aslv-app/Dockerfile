# VLH-CTF ASLV M3 — aslv-app (Laravel 11 skeleton on PHP 8.3 + Apache).
#
# Both compose services that build this directory use it with NO build
# overrides: `app` (full profile) and `app-std` (m3 standalone profile).
# No target stage needed — the final stage is the runtime image.

# ---------------------------------------------------------------------------
# Stage 1 — vendor via Composer.
# composer.json is the only input, so this layer caches across source edits.
# ---------------------------------------------------------------------------
FROM composer:2 AS vendor

WORKDIR /app

# --no-scripts skips artisan hooks (this stage has no app, only composer.json);
# --ignore-platform-reqs keeps the composer image's extension set from vetoing
# the install. laravel/framework ^11 lands in vendor/.
COPY composer.json ./
RUN composer install \
        --no-dev \
        --no-scripts \
        --prefer-dist \
        --no-interaction \
        --no-progress \
        --ignore-platform-reqs

# ---------------------------------------------------------------------------
# Stage 2 — runtime (php:8.3-apache ships mbstring, openssl, pdo_sqlite,
# sqlite3, tokenizer, etc. — everything Laravel 11 needs).
# ---------------------------------------------------------------------------
FROM php:8.3-apache

LABEL 811911.vlh="1" \
      vlh.product="aslv" \
      vlh.module="aslv-app" \
      vlh.unit="m3"

ENV APACHE_DOCUMENT_ROOT=/var/www/html/public \
    APP_ENV=production \
    APP_DEBUG=false \
    APP_URL= \
    DB_CONNECTION=sqlite \
    DB_DATABASE=/data/app.db \
    SESSION_DRIVER=database \
    SESSION_LIFETIME=120 \
    LOG_CHANNEL=stderr \
    CACHE_STORE=file

WORKDIR /var/www/html

# Vendored dependencies first (layer cache), then the application tree.
COPY --from=vendor /app/vendor ./vendor
COPY app ./app
COPY bootstrap ./bootstrap
COPY config ./config
COPY database ./database
COPY public ./public
COPY routes ./routes
COPY resources ./resources
COPY artisan ./
COPY .env.example ./
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
COPY docker/000-lab.conf /etc/apache2/sites-available/000-lab.conf

# Apache: DocumentRoot → public/ with .htaccess-driven rewrites (AllowOverride
# All lives in 000-lab.conf), executable entrypoint, then writable dirs for
# Laravel (compiled views, cache, logs) and the volume mounts (/data sqlite +
# lab state, /registry flag registry). Named volumes inherit this ownership on
# first use; the entrypoint re-asserts it after seeding (artisan runs as root,
# Apache workers are www-data).
RUN chmod 0755 /usr/local/bin/entrypoint.sh \
    && a2enmod rewrite \
    && a2dissite 000-default \
    && a2ensite 000-lab \
    && mkdir -p storage/framework/cache/data \
              storage/framework/sessions \
              storage/framework/views \
              storage/logs \
              bootstrap/cache \
              /data /registry \
    && chown -R www-data:www-data storage bootstrap/cache /data /registry

EXPOSE 80

# entrypoint.sh: volumes → .env/APP_KEY → fresh flags → migrate --seed →
# chown → exec CMD.
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["apache2-foreground"]
