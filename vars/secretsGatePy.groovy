def call(Map config = [:]) {

    String report   = config.get('report', 'cx_result.json')
    int maxAgeDays  = config.get('maxAgeDays', 10)

    writeFile(
        file: 'gate_secrets.py',
        text: libraryResource('gate_secrets.py')
    )

    sh """
      chmod +x gate_secrets.py
      python3 gate_secrets.py ${report} ${maxAgeDays}
    """
}
