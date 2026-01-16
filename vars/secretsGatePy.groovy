def call(Map config = [:]) {

    String report   = config.get('report', 'cx_result.json')
    int maxAgeDays  = config.get('maxAgeDays', 10)

    writeFile(
        file: 'gate_secrets.py',
        text: libraryResource('gate_secrets.py')
    )

    sh """
      if ! command -v python3 >/dev/null 2>&1; then
        echo "⚠️  'python3' não encontrado. Continuando pipeline sem verificação de secrets."
        exit 0
      fi

      chmod +x gate_secrets.py
      python3 gate_secrets.py ${report} ${maxAgeDays}
    """
}
