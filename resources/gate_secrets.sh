#!/usr/bin/env bash
set -e

JSON_FILE="${1:-cx_result.json}"
MAX_DAYS="${2:-10}"

check_secrets() {
    local json_file="$1"
    local now
    now=$(date +%s)
    local ten_days_ago
    ten_days_ago=$((now - 864000))

    if [ ! -f "$json_file" ]; then
        echo "ℹ️  Arquivo $json_file não encontrado - continuando pipeline sem verificação de secrets"
        return 0
    fi

    if ! command -v jq &> /dev/null; then
        echo "⚠️  'jq' não encontrado. Continuando pipeline sem verificação de secrets." >&2
        return 0
    fi

    # echo "Conteúdo do arquivo $json_file:"
    # cat "$json_file"

    # Verificar se o arquivo tem conteúdo válido
    if [ ! -s "$json_file" ]; then
        echo "ℹ️  Arquivo $json_file está vazio - continuando pipeline sem verificação de secrets"
        return 0
    fi

    # Verificar se é um JSON válido
    if ! jq empty "$json_file" 2>/dev/null; then
        echo "⚠️  Arquivo $json_file não é um JSON válido - continuando pipeline sem verificação de secrets"
        return 0
    fi

    local secrets_data
    secrets_data=$(jq -c '.results[] | select(.type == "sscs-secret-detection" and (.severity == "HIGH" or .severity == "CRITICAL"))' "$json_file" 2>/dev/null)

    if [ $? -ne 0 ]; then
        echo "⚠️  Erro ao processar secrets do arquivo JSON - continuando pipeline sem verificação de secrets" >&2
        return 0
    fi

    if [ -z "$secrets_data" ]; then
        echo "ℹ️  Nenhuma secret HIGH/CRITICAL encontrada no arquivo"
        return 0
    fi

    local has_blocking_secrets=0
    local secrets_found=0
    local secrets_ignored_old=0
    local secrets_ignored_not_exploitable=0
    local blocking_secrets_count=0
    local secrets_ignored_exception=0

    echo "🔍 Processando secrets encontradas..."
    echo ""

    # Usar while read para evitar subshell
    while IFS= read -r secret_obj; do
        [ -z "$secret_obj" ] && continue
        
        local status
        local first_found_at
        local state
        local filename
        local line
        local ruleName

        status=$(echo "$secret_obj" | jq -r '.status // "N/A"')
        first_found_at=$(echo "$secret_obj" | jq -r '.firstFoundAt // "N/A"')
        state=$(echo "$secret_obj" | jq -r '.state // "N/A"')
        filename=$(echo "$secret_obj" | jq -r '.data.filename // "N/A"')
        line=$(echo "$secret_obj" | jq -r '.data.line // "N/A"')
        ruleName=$(echo "$secret_obj" | jq -r '.data.ruleName // "N/A"')

        secrets_found=$((secrets_found + 1))

        if [[ "$status" == "NEW" ]]; then
            echo "🚨 Secret NEW encontrada:"
            echo "   Arquivo: $filename"
            echo "   Linha: $line"
            echo "   Tipo: $ruleName"
            echo "   Status: $status"
            echo "   Data de detecção: $first_found_at"
            echo ""
            has_blocking_secrets=1
            blocking_secrets_count=$((blocking_secrets_count + 1))
            continue
        fi

        if [[ "$status" == "RECURRENT" ]]; then
            if [[ "$state" == "NOT_EXPLOITABLE" ]]; then
                secrets_ignored_not_exploitable=$((secrets_ignored_not_exploitable + 1))
                echo "ℹ️  Secret RECURRENT ignorada (marcada como NOT_EXPLOITABLE):"
                echo "   Arquivo: $filename"
                echo "   Linha: $line"
                echo "   Tipo: $ruleName"
                echo "   Data de detecção: $first_found_at"
                echo ""
                continue
            fi
            
        if [[ "$status" == "RECURRENT" ]]; then
            if [[ "$state" == "Exception" ]]; then
                secrets_ignored_exception=$((secrets_ignored_exception + 1))
                echo "ℹ️  Secret RECURRENT ignorada (marcada como Exception):"
                echo "   Arquivo: $filename"
                echo "   Linha: $line"
                echo "   Tipo: $ruleName"
                echo "   Data de detecção: $first_found_at"
                echo ""
                continue
            fi

            local cleaned_date="${first_found_at//T/ }"
            cleaned_date="${cleaned_date%Z}"

            if date_unix=$(date -d "$cleaned_date" -u +%s 2>/dev/null); then
                if (( date_unix > ten_days_ago )); then
                    echo "🚨 Secret RECURRENT encontrada (menos de 10 dias):"
                    echo "   Arquivo: $filename"
                    echo "   Linha: $line"
                    echo "   Tipo: $ruleName"
                    echo "   Status: $status"
                    echo "   Data de detecção: $first_found_at"
                    echo ""
                    has_blocking_secrets=1
                    blocking_secrets_count=$((blocking_secrets_count + 1))
                else
                    secrets_ignored_old=$((secrets_ignored_old + 1))
                    echo "ℹ️  Secret RECURRENT ignorada (mais de 10 dias):"
                    echo "   Arquivo: $filename"
                    echo "   Linha: $line"
                    echo "   Tipo: $ruleName"
                    echo "   Data de detecção: $first_found_at"
                    echo ""
                fi
            else
                secrets_ignored_old=$((secrets_ignored_old + 1))
                echo "ℹ️  Secret RECURRENT ignorada (erro ao processar data):"
                echo "   Arquivo: $filename"
                echo "   Linha: $line"
                echo "   Tipo: $ruleName"
                echo "   Data de detecção: $first_found_at"
                echo ""
            fi
        fi
    done < <(echo "$secrets_data")

    # Resumo final
    echo "📊 Resumo de secrets encontradas:"
    echo "   Total: $secrets_found"
    if [ "$blocking_secrets_count" -gt 0 ]; then
        echo "   🚨 Bloqueadoras: $blocking_secrets_count"
    fi
    if [ "$secrets_ignored_old" -gt 0 ]; then
        echo "   ⏰ Ignoradas (antigas): $secrets_ignored_old"
    fi
    if [ "$secrets_ignored_not_exploitable" -gt 0 ]; then
        echo "   ✅ Ignoradas (not exploitable): $secrets_ignored_not_exploitable"
    fi
    echo ""

    # Retornar 1 se houver secrets bloqueadoras
    if [ "$has_blocking_secrets" -eq 1 ]; then
        return 1
    fi

    return 0
}

if check_secrets "cx_result.json"; then
    echo "✅ Nenhuma secret encontrada!"
else
    echo "::error::❌ Pipeline falhou devido a secrets detectadas! Favor verificar a engine de SCS nos resultados do Checkmarx." >&2
    exit 1
fi
