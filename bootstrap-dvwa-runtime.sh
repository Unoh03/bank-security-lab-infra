#!/usr/bin/env bash
set -Eeuo pipefail

umask 077

ADMIN_CNF="${1:-/tmp/dvwa-admin.cnf}"
APP_ENV="${2:-/tmp/dvwa.env}"
NAMESPACE="${3:-web}"
SECRET_NAME="${4:-dvwa-db}"
RDS_CA="/tmp/aws-rds-global-bundle.pem"

cleanup() {
  rm -f -- "$ADMIN_CNF" "$APP_ENV" "$RDS_CA"
}
trap cleanup EXIT

fail() {
  printf 'DVWA runtime bootstrap failed: %s\n' "$1" >&2
  exit 1
}

for command_name in curl mariadb kubectl; do
  command -v "$command_name" >/dev/null 2>&1 ||
    fail "required command is unavailable: $command_name"
done

curl --fail --silent --show-error --location \
  --output "$RDS_CA" \
  https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem
chmod 0600 "$RDS_CA"

[[ -f "$ADMIN_CNF" ]] || fail "database admin option file is missing"
[[ -f "$APP_ENV" ]] || fail "application environment file is missing"
[[ "$NAMESPACE" =~ ^[a-z0-9]([-a-z0-9]*[a-z0-9])?$ ]] ||
  fail "invalid Kubernetes namespace"
[[ "$SECRET_NAME" =~ ^[a-z0-9]([-a-z0-9]*[a-z0-9])?$ ]] ||
  fail "invalid Kubernetes Secret name"

declare -A app_config=()
while IFS='=' read -r key value; do
  [[ -n "$key" ]] || continue
  app_config["$key"]="$value"
done <"$APP_ENV"

for key in DB_SERVER DB_PORT DB_DATABASE DB_USER DB_PASSWORD; do
  [[ -n "${app_config[$key]:-}" ]] || fail "required application setting is missing: $key"
done

[[ "${app_config[DB_PORT]}" =~ ^[0-9]+$ ]] ||
  fail "DB_PORT must be numeric"
[[ "${app_config[DB_DATABASE]}" =~ ^[A-Za-z0-9_]+$ ]] ||
  fail "DB_DATABASE contains unsupported characters"
[[ "${app_config[DB_USER]}" =~ ^[A-Za-z0-9_]+$ ]] ||
  fail "DB_USER contains unsupported characters"
[[ "${app_config[DB_PASSWORD]}" =~ ^[A-Za-z0-9]+$ ]] ||
  fail "DB_PASSWORD contains unsupported characters"

database_name="${app_config[DB_DATABASE]}"
database_user="${app_config[DB_USER]}"
database_password="${app_config[DB_PASSWORD]}"

printf 'Waiting for the MariaDB control connection...\n'
ready=false
for _ in $(seq 1 60); do
  if mariadb --defaults-extra-file="$ADMIN_CNF" --protocol=TCP \
    --connect-timeout=5 --execute='SELECT 1' >/dev/null 2>&1; then
    ready=true
    break
  fi
  sleep 10
done
[[ "$ready" == "true" ]] ||
  fail "MariaDB did not become reachable within 10 minutes"

mariadb --defaults-extra-file="$ADMIN_CNF" --protocol=TCP >/dev/null <<SQL
CREATE DATABASE IF NOT EXISTS \`${database_name}\`
  CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS '${database_user}'@'%'
  IDENTIFIED BY '${database_password}';
ALTER USER '${database_user}'@'%'
  IDENTIFIED BY '${database_password}';
GRANT ALL PRIVILEGES ON \`${database_name}\`.* TO '${database_user}'@'%';
FLUSH PRIVILEGES;
SQL

kubectl create namespace "$NAMESPACE" \
  --dry-run=client -o yaml |
  kubectl apply -f - >/dev/null

kubectl -n "$NAMESPACE" create secret generic "$SECRET_NAME" \
  --from-env-file="$APP_ENV" \
  --dry-run=client -o yaml |
  kubectl apply -f - >/dev/null

kubectl -n "$NAMESPACE" get secret "$SECRET_NAME" -o name >/dev/null

printf 'DVWA database, application user, and Kubernetes Secret are ready.\n'
