def call(Map config = [:]) {

    String report     = config.get('report', 'cx_result.json')
    int maxAgeDays    = config.get('maxAgeDays', 10)

    echo "Executando Policy Gate - Secrets"
    echo "Relatório: ${report}"
    echo "Idade máxima permitida: ${maxAgeDays} dias"

    writeFile(
        file: 'gate_secrets.sh',
        text: libraryResource('gate_secrets.sh')
    )

    sh """
      ./gate_secrets.sh ${report} ${maxAgeDays}
    """
}
