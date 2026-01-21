def call(Map config = [:]) {

    String report = config.get('report', 'cx_result.json')

    // Variáveis esperadas via Jenkinsfile
    String bucket      = env.EXCEPTIONS_BUCKET ?: ""
    String key         = env.EXCEPTIONS_KEY ?: "exceptions.json"
    String projectName = env.PROJECT_NAME ?: ""

    echo "🔐 Executando Security Gate (Secrets) via Python embutido"

    sh """
        set -e

        echo "🐍 Verificando Python3..."
        if ! command -v python3 >/dev/null 2>&1; then
            echo "⚠️  python3 não encontrado — pipeline continuará SEM validação de secrets."
            exit 0
        fi

        echo "📦 Verificando dependência boto3..."

        # Testa rapidamente se boto3 já está instalado
        if python3 - << 'EOS'
try:
    import boto3
    print("boto3 OK")
except ImportError:
    raise SystemExit(1)
EOS
        then
            echo "✔ boto3 já instalado."
        else
            echo "⚠ boto3 não encontrado — instalando agora..."
            python3 -m ensurepip --user || true

            # tenta instalar boto3 localmente (modo user, sem root)
            if pip3 install --user boto3; then
                echo "✔ boto3 instalado com sucesso."
            else
                echo "❌ Falha ao instalar boto3 — validação de secrets não será executada."
                exit 0
            fi

            # adiciona paths locais, garantindo que boto3 seja encontrado
            export PYTHONPATH="\$HOME/.local/lib/python3*/site-packages:\$PYTHONPATH"
        fi

        echo "📥 Executando Security Gate..."

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


# ==========================
#  EXECUÇÃO PRINCIPAL
# ==========================

exceptions = get_exceptions_from_s3(EXC_BUCKET, EXC_KEY)

if is_project_exception(PROJECT, exceptions):
    print("⚠️  Projeto está NA LISTA DE EXCEÇÕES. Nenhum bloqueio será aplicado.")
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
