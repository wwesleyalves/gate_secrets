def call(Map config = [:]) {

    String report = config.get('report', 'cx_result.json')

    // Variáveis vindas do Jenkinsfile
    String bucket      = env.EXCEPTIONS_BUCKET ?: ""
    String key         = env.EXCEPTIONS_KEY ?: "exceptions.json"
    String projectName = env.PROJECT_NAME ?: ""

    echo "🔐 Executando Security Gate (Secrets) via Python + AWS CLI"

    sh """
        set -e

        echo "🐍 Verificando Python3..."
        if ! command -v python3 >/dev/null 2>&1; then
            echo "⚠️ python3 não encontrado — pipeline continuará SEM validação de secrets."
            exit 0
        fi

        echo "🪣 Baixando lista de exceções do S3 via AWS CLI..."
        if command -v aws >/dev/null 2>&1; then
            if [ -n "${bucket}" ]; then
                aws s3 cp "s3://${bucket}/${key}" exceptions.json || echo "⚠️ Não foi possível baixar exceções — arquivo ignorado."
            else
                echo "⚠️ Bucket não configurado — ignorando exceções."
            fi
        else
            echo "⚠️ AWS CLI não encontrada — ignorando exceções."
        fi

        echo "📥 Executando Security Gate interno..."

        python3 - <<'EOF'
import json
import os
import sys

report_file = "${report}"
PROJECT     = "${projectName}"

# ==========================
# LEITURA DAS EXCEÇÕES (SEM BOTO3)
# ==========================
def load_exceptions():
    if not os.path.isfile("exceptions.json"):
        print("⚠️ Arquivo exceptions.json não encontrado — nenhuma exceção aplicada.")
        return []

    try:
        with open("exceptions.json") as f:
            data = json.load(f)
            return data.get("projects", [])
    except Exception as e:
        print(f"⚠️ Falha ao carregar exceptions.json: {e}")
        return []


def is_project_exception(project, exceptions):
    proj = project.strip().lower()
    normalized = [p.strip().lower() for p in exceptions]
    return proj in normalized


# ==========================
# VALIDAÇÃO DE SECRETS (SEU CÓDIGO)
# ==========================
def check_secrets(json_file):
    if not os.path.isfile(json_file):
        print(f"Arquivo {json_file} não encontrado.")
        return 0

    if os.path.getsize(json_file) == 0:
        print(f"Arquivo {json_file} está vazio.")
        return 0

    try:
        with open(json_file) as f:
            data = json.load(f)
    except:
        print("Erro ao carregar JSON.")
        return 0

    results = data.get("results", [])
    secrets_data = [
        r for r in results
        if r.get("type") == "sscs-secret-detection"
        and r.get("severity") in ("HIGH", "CRITICAL")
    ]

    if not secrets_data:
        print("ℹ️ Nenhuma secret crítica encontrada.")
        return 0

    blocking = 0

    for s in secrets_data:
        status = s.get("status")
        state = s.get("state")

        if status == "NEW":
            print("🚨 Secret NEW encontrada — bloqueia.")
            blocking = 1
            continue

        if status == "RECURRENT":
            if state == "NOT_EXPLOITABLE":
                print("ℹ️ RECURRENT NOT_EXPLOITABLE — ignorada.")
            else:
                print("🚨 Secret RECURRENT — bloqueia.")
                blocking = 1

    return blocking


# ==========================
# EXECUÇÃO PRINCIPAL
# ==========================
exceptions = load_exceptions()

if is_project_exception(PROJECT, exceptions):
    print("⚠️ Projeto está NA LISTA DE EXCEÇÕES. Nenhum bloqueio será aplicado.")
    check_secrets(report_file)
    sys.exit(0)

exit_code = check_secrets(report_file)

if exit_code == 0:
    print("✅ Nenhuma secret bloqueadora encontrada.")
else:
    print("❌ Secrets encontradas — bloqueando pipeline.")
    sys.exit(1)

EOF
    """
}
