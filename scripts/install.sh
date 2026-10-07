#!/usr/bin/env bash
set -euo pipefail
cd /opt/remote

if [ ! -d venv ]; then
  python3 -m venv venv
fi

./venv/bin/pip install --upgrade pip
./venv/bin/pip install -r requirements.txt

if [ ! -f .env ]; then
  cp .env.example .env
  echo "Edite /opt/remote/.env antes de iniciar os serviços."
fi

mkdir -p game_patches mrwanx_system/data site mitmproxy-conf

[ -f mrwanx_system/data/allowed_ips.json ] || printf '{}\n' > mrwanx_system/data/allowed_ips.json
[ -f mrwanx_system/data/freeze_state.json ] || printf '{"frozen": false}\n' > mrwanx_system/data/freeze_state.json

cp config/remote-api.service /etc/systemd/system/remote-api.service
cp config/remote-proxy.service /etc/systemd/system/remote-proxy.service
systemctl daemon-reload

echo "Base instalada."
echo "Edite .env, configure nginx e ative remote-api/remote-proxy."
