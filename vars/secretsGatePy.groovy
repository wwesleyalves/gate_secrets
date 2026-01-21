def call(Map config = [:]) {

    String report = config.get('report', 'cx_result.json')

    // Variáveis esperadas para exceções via S3
    String bucket = env.EXCEPTIONS_BUCKET ?: ""
    String key    = env.EXCEPTIONS_KEY ?: "exceptions.json"
    String projectName = env.PROJECT_NAME ?: ""

    echo "🔐 Executando Security Gate (Secrets) via Python embutido"

    sh """
        set -e

        if ! command -v python3 >/dev/null 2>&1; then
            echo "⚠️  python3 não encontrado — pipeline continuará sem validação de secrets."
            exit 0
        fi

        echo "📥 Executando Security Gate interno..."

        python3 - <<'EOF'
import json
import os
import sys
import boto3
from botocore.exceptions import ClientError

report_file = "${report}"
EXC_BUCKET  = "${bucket}"
EXC_KEY     = "${key}"
PROJECT     = "${projectName}"

def get_exceptions_from_s3(bucket, key):
    if not bucket:
        print("⚠️  EXCEPTIONS_BUCKET não configurado — exceções ignoradas.")
        return []

    try:
        s3 = boto3.client(
            "s3",
            aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
            aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
        )
        obj = s3.get_object(Bucket=bucket, Key=key)
        data = obj["Body"].read().decode("utf-8")
        json_data = json.loads(data)
        return json_data.get("projects", [])
    except Exception as e:
        print(f"⚠️  Falha ao buscar exceções no S3: {e}")
        return []


def is_project_exception(project, exceptions):
    proj = project.strip().lower()
    normalized = [p.strip().lower() for p in exceptions]
    return proj in normalized


# ▼▼▼==============================
#  AQUI ENTRA O TEU CÓDIGO ORIGINAL
# (check_secrets meninim abaixo)
# ==============================▼▼▼
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
        print("ℹ️  Nenhuma secret crítica encontrada.")
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
                print("ℹ️  RECURRENT NOT_EXPLOITABLE — ignorada.")
            else:
                print("🚨 Secret RECURRENT — bloqueia.")
                blocking = 1

    return blocking


# ==============================
#  EXECUÇÃO PRINCIPAL
# ==============================
exceptions = get_exceptions_from_s3(EXC_BUCKET, EXC_KEY)

if is_project_exception(PROJECT, exceptions):
    print("⚠️  Projeto está NA LISTA DE EXCEÇÕES. Nenhum bloqueio será aplicado.")
    check_secrets(report_file)
    sys.exit(0)

# Caso normal: aplicar regra de bloqueio
exit_code = check_secrets(report_file)

if exit_code == 0:
    print("✅ Nenhuma secret bloqueadora encontrada.")
else:
    print("❌ Secrets encontradas — bloqueando pipeline.")
    sys.exit(1)

EOF
    """
}
