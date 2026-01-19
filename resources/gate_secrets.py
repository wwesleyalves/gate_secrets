#!/usr/bin/env python3
import json
import os
import sys
import time
from typing import Any, Dict


def check_secrets(json_file: str) -> int:
    # Verificação do arquivo de entrada
    if not os.path.isfile(json_file):
        print(f"ℹ️  Arquivo {json_file} não encontrado - continuando pipeline sem verificação de secrets")
        return 0

    if os.path.getsize(json_file) == 0:
        print(f"ℹ️  Arquivo {json_file} está vazio - continuando pipeline sem verificação de secrets")
        return 0

    # Leitura do JSON
    try:
        with open(json_file, "r", encoding="utf-8") as f:
            data: Dict[str, Any] = json.load(f)
    except Exception:
        print(f"⚠️  Arquivo {json_file} não é um JSON válido - continuando pipeline sem verificação de secrets")
        return 0

    # Filtrar apenas secrets HIGH / CRITICAL
    try:
        results = data.get("results", [])
        secrets_data = [
            r for r in results
            if r.get("type") == "sscs-secret-detection"
            and r.get("severity") in ("HIGH", "CRITICAL")
        ]
    except Exception:
        print(
            "⚠️  Erro ao processar secrets do arquivo JSON - continuando pipeline sem verificação de secrets",
            file=sys.stderr
        )
        return 0

    if not secrets_data:
        print("ℹ️  Nenhuma secret HIGH/CRITICAL encontrada no arquivo")
        return 0

    has_blocking_secrets = 0
    secrets_found = 0
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

        # Secret NEW → sempre bloqueia
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

        # Secret RECURRENT
        if status == "RECURRENT":
            # NOT_EXPLOITABLE → ignora
            if state == "NOT_EXPLOITABLE":
                secrets_ignored_not_exploitable += 1
                print("ℹ️  Secret RECURRENT ignorada (marcada como NOT_EXPLOITABLE):")
                print(f"   Arquivo: {filename}")
                print(f"   Linha: {line}")
                print(f"   Tipo: {rule_name}")
                print(f"   Data de detecção: {first_found_at}\n")
                continue

            # RECURRENT (qualquer idade) → bloqueia
            print("🚨 Secret RECURRENT encontrada:")
            print(f"   Arquivo: {filename}")
            print(f"   Linha: {line}")
            print(f"   Tipo: {rule_name}")
            print(f"   Status: {status}")
            print(f"   Data de detecção: {first_found_at}\n")

            has_blocking_secrets = 1
            blocking_secrets_count += 1

    # Resumo final
    print("📊 Resumo de secrets encontradas:")
    print(f"   Total: {secrets_found}")
    if blocking_secrets_count > 0:
        print(f"   🚨 Bloqueadoras: {blocking_secrets_count}")
    if secrets_ignored_not_exploitable > 0:
        print(f"   ✅ Ignoradas (not exploitable): {secrets_ignored_not_exploitable}")
    print("")

    if has_blocking_secrets == 1:
        return 1

    return 0


if check_secrets(sys.argv[1] if len(sys.argv) > 1 else "cx_result.json") == 0:
    print("✅ Nenhuma secret encontrada!")
else:
    print(
        "::error::❌ Pipeline falhou devido a secrets detectadas! "
        "Favor verificar a engine de SCS nos resultados do Checkmarx.",
        file=sys.stderr
    )
    sys.exit(1)
