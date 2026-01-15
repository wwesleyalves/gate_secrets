#!/usr/bin/env bash
set -e

JSON_FILE="${1:-cx_result.json}"
MAX_DAYS="${2:-10}"

check_secrets() {
    local json_file="$1"
    local max_days="$2"
    local now
    now=$(date +%s)
    local limit_date=$((now - (max_days * 86400)))

    if [ ! -f "$json_file" ]; then
        echo "Arquivo $json_file não encontrado - gate ignorado"
        return 0
    fi

    if ! command -v jq >/dev/null 2>&1; then
        echo "'jq' não encontrado - gate ignorado"
        return 0
    fi

    if [ ! -s "$json_file" ]; then
        echo "Arquivo $json_file vazio - gate ignorado"
        return 0
    fi

    if ! jq empty "$json_file" 2>/dev/null; then
        echo "JSON inválido - gate ignorado"
        return 0
    fi

    local secrets
    secrets=$(jq -c '.results[] | select(.type=="sscs-secret-detection" and (.severity=="HIGH" or .severity=="CRITICAL"))' "$json_file")

    [ -z "$secrets" ] && {
        echo "Nenhuma secret HIGH/CRITICAL encontrada"
        return 0
    }

    local blocking=0
    local count=0

    echo "Iniciando Policy Gate - Secrets"
    echo ""

    while IFS= read -r s; do
        status=$(echo "$s" | jq -r '.status')
        state=$(echo "$s" | jq -r '.state')
        found=$(echo "$s" | jq -r '.firstFoundAt')
        file=$(echo "$s" | jq -r '.data.filename')
        line=$(echo "$s" | jq -r '.data.line')
        rule=$(echo "$s" | jq -r '.data.ruleName')

        if [[ "$status" == "NEW" ]]; then
            echo "SECRET NEW: $file:$line ($rule)"
            blocking=1
            count=$((count + 1))
            continue
        fi

        if [[ "$status" == "RECURRENT" && "$state" != "NOT_EXPLOITABLE" ]]; then
            ts=$(date -d "${found//T/ }" +%s 2>/dev/null || echo 0)
            if (( ts > limit_date )); then
                echo "SECRET RECURRENT (<${max_days}d): $file:$line ($rule)"
                blocking=1
                count=$((count + 1))
            fi
        fi
    done <<< "$secrets"

    echo ""
    echo "Secrets bloqueadoras: $count"

    [ "$blocking" -eq 1 ] && return 1 || return 0
}

check_secrets "$JSON_FILE" "$MAX_DAYS"
