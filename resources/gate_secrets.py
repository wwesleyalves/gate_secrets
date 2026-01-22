#!/usr/bin/env python3
import json
import os
import sys
from typing import Any, Dict, List


# =========================================================
# CARREGAMENTO DE EXCEÇÕES
# =========================================================
def load_exceptions(exceptions_file: str) -> List[str]:
    if not exceptions_file or not os.path.isfile(exceptions_file):
        print("ℹ️  Arquivo de exceções não encontrado — nenhuma exceção aplicada")
        return []

    try:
        with open(exceptions_file, "r", encoding="utf-8") as f:
            data = json.load(f)
            return [p.strip().lower() for p in data.get("projects", [])]
    except Exception as e:
        print(f"⚠️  Erro ao carregar exceções: {e}")
        return []


def is_project_exception(project: str, exceptions: List[str]) -> bool:
    if not project:
        return False
    return project.strip().lower() in exceptions


# =========================================================
# VALIDAÇÃO DE SECRETS
# =========================================================
def check_secrets(json_file: str) -> int:
    if not os.path.isfile(json_file):
        print(f"ℹ️  Arquivo {json_file} não encontrado - continuando pipeline")
        return 0

    if os.path.getsize(json_file) == 0:
        print(f"ℹ️  Arquivo {json_file} está vazio - continuando pipeline")
        return 0

    try:
        with open(json_file, "r", encoding="utf-8") as f:
            data: Dict[str, Any] = json.load(f)
    except Exception:
        print(f"⚠️  Arquivo {json_file} não é um JSON válido - continuando pipeline")
        return 0

    try:
        results = data.get("results", [])
        secrets_data = [
            r for r in results
            if r.get("type") == "sscs-secret-detection"
            and r.get("severity") in ("HIGH", "CRITICAL")
        ]
    except Exception:
        print("⚠️  Erro ao processar secrets do JSON")
        return 0

    if not secrets_data:
        print("ℹ️  Nenhuma secret HIGH/CRITICAL encontrada")
        return 0

    has_blocking = 0
    total = 0
    ignored = 0
    blocking_count = 0

    print("🔍 Processando secrets encontradas...\n")

    for secret in secrets_data:
        total += 1

        status = secret.get("status", "N/A")
        state = secret.get("state", "N/A")
        first_found = secret.get("firstFoundAt", "N/A")
        data_obj = secret.get("data", {})

        filename = data_obj.get("filename", "N/A")
        line = data_obj.get("line", "N/A")
        rule = data_obj.get("ruleName", "N/A")

        if status == "NEW":
            print("🚨 Secret NEW encontrada:")
            print(f"   Arquivo: {filename}")
            print(f"   Linha: {line}")
            print(f"   Tipo: {rule}")
            print(f"   Data: {first_found}\n")
            has_blocking = 1
            blocking_count += 1
            continue

        if status == "RECURRENT":
            if state == "NOT_EXPLOITABLE":
                ignored += 1
                print("ℹ️  Secret RECURRENT ignorada (NOT_EXPLOITABLE):")
                print(f"   Arquivo: {filename}")
                print(f"   Linha: {line}")
                print(f"   Tipo: {rule}\n")
                continue

            print("🚨 Secret RECURRENT encontrada:")
            print(f"   Arquivo: {filename}")
            print(f"   Linha: {line}")
            print(f"   Tipo: {rule}")
            print(f"   Data: {first_found}\n")
            has_blocking = 1
            blocking_count += 1

    print("📊 Resumo de secrets:")
    print(f"   Total: {total}")
    if blocking_count:
        print(f"   🚨 Bloqueadoras: {blocking_count}")
    if ignored:
        print(f"   ✅ Ignoradas (NOT_EXPLOITABLE): {ignored}")
    print("")

    return 1 if has_blocking else 0


# =========================================================
# EXECUÇÃO PRINCIPAL
# =========================================================
if __name__ == "__main__":

    report_file = sys.argv[1] if len(sys.argv) > 1 else "cx_result.json"
    project_name = os.getenv("PROJECT_NAME", "")
    exceptions_file = os.getenv("EXCEPTIONS_FILE", "projects.json")

    exceptions = load_exceptions(exceptions_file)

    if is_project_exception(project_name, exceptions):
        print(
            f"⚠️  Projeto '{project_name}' está na lista de exceções — "
            "Security Gate de secrets NÃO será aplicado"
        )
        sys.exit(0)

    result = check_secrets(report_file)

    if result == 0:
        print("✅ Nenhuma secret bloqueadora encontrada")
        sys.exit(0)

    print(
        "::error::❌ Pipeline bloqueado devido a secrets detectadas!",
        file=sys.stderr
    )
    sys.exit(1)
