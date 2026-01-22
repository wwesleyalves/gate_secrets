def call(Map config = [:]) {

    String report = config.get('report', 'cx_result.json')
    String bucket      = env.EXCEPTIONS_BUCKET ?: ""
    String key         = env.EXCEPTIONS_KEY ?: "projects.json"
    String projectName = env.PROJECT_NAME ?: ""
    
    echo "Executando Security Gate de Secrets"
    
    writeFile(
        file: 'gate_secrets.py',
        text: libraryResource('gate_secrets.py')
    )

    sh """
      echo "Verificando Python3..."
      if ! command -v python3 >/dev/null 2>&1; then
        echo "⚠️  'python3' não encontrado. Continuando pipeline sem verificação de secrets."
        exit 0
      fi
      
      echo "Baixando exceções do S3..."
      if command -v aws >/dev/null 2>&1 && [ -n "${bucket}" ]; then
          aws s3 cp "s3://${bucket}/exceptions/${key}" projects.json \
            || echo "Falha ao baixar exceções — continuando sem exceções"
      else
          echo "AWS CLI ou bucket não configurado — sem exceções"
      fi

      export PROJECT_NAME="${projectName}"
      export EXCEPTIONS_FILE="projects.json"

      chmod +x gate_secrets.py
      python3 gate_secrets.py ${report}
    """
}
