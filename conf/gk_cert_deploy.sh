#!/bin/bash
# micro-monban: Let's Encrypt の証明書が取得・更新されたあとに certbot が呼ぶ
# （nginx に新しい証明書を読み込ませる）
if nginx -t >/dev/null 2>&1; then
  systemctl reload nginx
  logger -t gatekeeper "証明書を更新し nginx を再読み込みしました: ${RENEWED_DOMAINS:-}"
else
  logger -t gatekeeper "証明書は更新されたが nginx -t に失敗: ${RENEWED_DOMAINS:-}"
fi
