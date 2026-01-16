#!/usr/bin/env python3
import json
import os
import sys
import time
from datetime import datetime, timezone

JSON_FILE = sys.argv[1] if len(sys.argv) > 1 else "cx_result.json"
MAX_DAYS = int(sys.argv[2]) if len(sys.argv) > 2 else 10

TEN_DAYS_SECONDS = MAX_DAYS * 24 * 60 * 60


def check_secrets(json_file: str) -> int:
    now = int(time.time())
    ten_days_ago = now - TEN_DAYS_SECONDS

    if not os.path.isfile(json_file):
        print(f"ℹ️  Arquivo {json_file} não encontrado - continuando pipeline sem verificação de secrets")
        return 0

    if os.path.getsize(json_file) == 0:
        print(f"ℹ️  Arquivo {json_file} está vazio - continuando pipeline sem verificação de secrets")
        return 0

    try:
        with open(json_file, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        print(f"⚠️  Arquivo {json_file} não é um JSON válido - continuando pipeline sem verificação de secrets")
        return 0

    try:
        results = data.get("results", [])
        secrets_data = [
            r for r in results
            if r.get("type") == "sscs-secret-detection"
            and r.get("severity") in ("HIGH", "CRITICAL")
        ]
    except Exception:
        print("⚠️  Erro ao processar secrets do arquivo JSON - continuando pipeline sem verificação de secrets", file=sys.stderr)
        return 0

    if not secrets_data:
        print("ℹ️  Nenhuma secret HIGH/CRITICAL encontrada no arquivo")
        return 0

    has_blocking_secrets = 0
    secrets_found = 0
    secrets_ignored_old = 0
    secrets_ignored_not_exploitable = 0
    blocking_secrets_count = 0

    print("🔍 Processando secrets encontradas...\n")

    for secret in secrets_data:
        status = secret.get("status", "N/A")
        first_found_at = secret.get("firstFoundAt", "N/A")
        state = secret.get("state", "N/A")
        data_obj = secret.get("data", {})

        filename = data_obj.get("filename", "N/A")
        line = data_obj.get("line", "N/A")
        rule_name = data_obj.get("ruleName", "N/A")

        secrets_found += 1

        if status == "NEW":
            print("🚨 Secret NEW encontrada:")
            print(f"   Arquivo: {filename}")
            print(f"   Linha: {line}")
            print(f"   Tipo: {rule_name}")
            print(f"   Status: {status}")
            print(f"   Data de detecção: {first_found_at}\n")
            has_blocking_secrets = 1
            blocking_secrets_count += 1
            continue

        if status == "RECURRENT":
            if state == "NOT_EXPLOITABLE":
                secrets_ignored_not_exploitable += 1
                print("ℹ️  Secret RECURRENT ignorada (marcada como NOT_EXPLOITABLE):")
                print(f"   Arquivo: {filename}")
                print(f"   Linha: {line}")
                print(f"   Tipo: {rule_name}")
                print(f"   Data de detecção: {first_found_at}\n")
                continue

            try:
                cleaned_date = first_found_at.replace("T", " ").replace("Z", "")
                dt = datetime.strptime(cleaned_date, "%Y-%m-%d %H:%M:%S")
                date_unix = int(dt.replace(tzinfo=timezone.utc).timestamp())

                if date_unix > ten_days_ago:
                    print("🚨 Secret RECURRENT encontrada (menos de 10 dias):")
                    print(f"   Arquivo: {filename}")
                    print(f"   Linha: {line}")
                    print(f"   Tipo: {rule_name}")
                    print(f"   Status: {status}")
                    print(f"   Data de detecção: {first_found_at}\n")
                    has_blocking_secrets = 1
                    blocking_secrets_count += 1
                else:
                    secrets_ignored_old += 1
                    print("ℹ️  Secret RECURRENT ignorada (mais de 10 dias):")
                    print(f"   Arquivo: {filename}")
                    print(f"   Linha: {line}")
                    print(f"   Tipo: {rule_name}")
                    print(f"   Data de detecção: {first_found_at}\n")

            except Exception:
                secrets_ignored_old += 1
                print("ℹ️  Secret RECURRENT ignorada (erro ao processar data):")
                print(f"   Arquivo: {filename}")
                print(f"   Linha: {line}")
                print(f"   Tipo: {rule_name}")
                print(f"   Data de detecção: {first_found_at}\n")

    print("📊 Resumo de secrets encontradas:")
    print(f"   Total: {secrets_found}")
    if blocking_secrets_count > 0:
        print(f"   🚨 Bloqueadoras: {blocking_secrets_count}")
    if secrets_ignored_old > 0:
        print(f"   ⏰ Ignoradas (antigas): {secrets_ignored_old}")
    if secrets_ignored_not_exploitable > 0:
        print(f"   ✅ Ignoradas (not exploitable): {secrets_ignored_not_exploitable}")
    print("")

    if has_blocking_secrets == 1:
        return 1

    return 0


if check_secrets(JSON_FILE) == 0:
    print("✅ Nenhuma secret encontrada!")
else:
    print(
        "::error::❌ Pipeline falhou devido a secrets detectadas! "
        "Favor verificar a engine de SCS nos resultados do Checkmarx.",
        file=sys.stderr
    )
    sys.exit(1)
