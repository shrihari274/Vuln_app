// Helper function to create a text-based bar graph for reports
def generateBar(label, count, max_bar_width = 50) {
    if (count == 0) return ""
    // Use a different character for each report type for visual flair
    def bar_char = "█"
    if (label.toLowerCase().contains('secret')) bar_char = "🔑"
    if (label.toLowerCase().contains('malware')) bar_char = "🦠"

    def bar = bar_char * Math.min(count, max_bar_width)
    return "${label.padRight(10)} | ${bar}"
}

pipeline {
    agent any

    environment {
        // --- Configuration ---
        IMAGE_NAME = "vuln-flask-app:${BUILD_NUMBER}"
        DEEPFENCE_CONSOLE_URL = '192.168.74.125'
        SCANNER_VERSION = '2.5.2'

        // --- Failure Conditions (set to -1 to ignore a check) ---
        FAIL_ON_CRITICAL_VULNERABILITIES = 1
        FAIL_ON_HIGH_VULNERABILITIES = 5
        FAIL_ON_HIGH_SECRETS = 1
        FAIL_ON_HIGH_MALWARE = 1
    }

    stages {
        stage('🐙 1. Checkout Code') {
            steps {
                checkout scm
            }
        }

        stage('🐳 2. Build Docker Image') {
            steps {
                echo "Building Docker image: ${IMAGE_NAME}"
                sh "docker build -t ${IMAGE_NAME} ."
            }
        }

        stage('🛡️ 3. Scan for Vulnerabilities') {
            steps {
                script {
                    try {
                        echo "Scanning ${IMAGE_NAME} for vulnerabilities..."
                        // Use withCredentials to securely load the API key
                        withCredentials([string(credentialsId: 'deepfence-api-key', variable: 'DF_API_KEY')]) {
                            def scanJson = sh(
                                script: """
                                    docker run --rm --net=host -v /var/run/docker.sock:/var/run/docker.sock:rw \\
                                    -e DEEPFENCE_KEY=\${DF_API_KEY} \\
                                    quay.io/deepfenceio/deepfence_package_scanner_cli:${SCANNER_VERSION} \\
                                    -console-url=${DEEPFENCE_CONSOLE_URL} \\
                                    -source=${IMAGE_NAME} -scan-type=base,python \\
                                    -output json
                                """,
                                returnStdout: true
                            )

                            // --- Vulnerability Report Generation ---
                            def criticalCount = 0, highCount = 0, mediumCount = 0, lowCount = 0
                            if (scanJson) {
                                def data = readJSON(text: scanJson.trim())
                                data.each { scan ->
                                    if (scan.vulnerabilities) {
                                        scan.vulnerabilities.each { v ->
                                            switch(v.severity?.toLowerCase()) {
                                                case 'critical': criticalCount++; break
                                                case 'high':     highCount++; break
                                                case 'medium':   mediumCount++; break
                                                case 'low':      lowCount++; break
                                            }
                                        }
                                    }
                                }
                            }
                            def totalCount = criticalCount + highCount + mediumCount + lowCount

                            echo """
                            +--------------------------------------------------+
                            |           VULNERABILITY SCAN SUMMARY             |
                            +--------------------------------------------------+
                            | Total Vulnerabilities Found: ${totalCount.toString().padLeft(21)} |
                            +--------------------------------------------------+
                            ${generateBar('Critical', criticalCount)}
                            ${generateBar('High', highCount)}
                            ${generateBar('Medium', mediumCount)}
                            ${generateBar('Low', lowCount)}
                            +--------------------------------------------------+
                            """

                            // --- Failure Logic ---
                            def failBuild = false
                            def failureReasons = []
                            if (FAIL_ON_CRITICAL_VULNERABILITIES != -1 && criticalCount >= FAIL_ON_CRITICAL_VULNERABILITIES) {
                                failBuild = true
                                failureReasons.add("Found ${criticalCount} critical vulnerabilities (threshold: ${FAIL_ON_CRITICAL_VULNERABILITIES})")
                            }
                            if (FAIL_ON_HIGH_VULNERABILITIES != -1 && highCount >= FAIL_ON_HIGH_VULNERABILITIES) {
                                failBuild = true
                                failureReasons.add("Found ${highCount} high vulnerabilities (threshold: ${FAIL_ON_HIGH_VULNERABILITIES})")
                            }

                            if (failBuild) {
                                error("BUILD FAILED: ${failureReasons.join(', ')}")
                            } else {
                                echo "✅ Vulnerability scan passed!"
                            }
                        }
                    } catch (e) {
                        echo "ERROR: Vulnerability scan failed. The scanner command returned an error."
                        error("Failing build due to vulnerability scan failure.")
                    }
                }
            }
        }

        stage('🤫 4. Scan for Secrets') {
            steps {
                script {
                    try {
                        echo "Scanning ${IMAGE_NAME} for secrets..."
                        def scanJson = sh(
                            script: """
                                docker run --rm --net=host -v /var/run/docker.sock:/var/run/docker.sock:rw \\
                                quay.io/deepfenceio/deepfence_secret_scanner:${SCANNER_VERSION} \\
                                -image-name=${IMAGE_NAME} \\
                                -output json
                            """,
                            returnStdout: true
                        )

                        // --- Secret Report Generation ---
                        def highSecrets = 0, mediumSecrets = 0, lowSecrets = 0
                        if(scanJson) {
                            def data = readJSON(text: scanJson.trim())
                            if (data.secrets) {
                                data.secrets.each { secret ->
                                    switch(secret.Severity?.toLowerCase()) {
                                        case 'high':   highSecrets++; break
                                        case 'medium': mediumSecrets++; break
                                        case 'low':    lowSecrets++; break
                                    }
                                }
                            }
                        }
                        def totalSecrets = highSecrets + mediumSecrets + lowSecrets

                        echo """
                        +--------------------------------------------------+
                        |             SECRET SCAN SUMMARY                   |
                        +--------------------------------------------------+
                        | Total Secrets Found: ${totalSecrets.toString().padLeft(29)} |
                        +--------------------------------------------------+
                        ${generateBar('Secrets-H', highSecrets)}
                        ${generateBar('Secrets-M', mediumSecrets)}
                        ${generateBar('Secrets-L', lowSecrets)}
                        +--------------------------------------------------+
                        """

                        // --- Failure Logic ---
                        if (FAIL_ON_HIGH_SECRETS != -1 && highSecrets >= FAIL_ON_HIGH_SECRETS) {
                            error("BUILD FAILED: Found ${highSecrets} high-severity secrets (threshold: ${FAIL_ON_HIGH_SECRETS})")
                        } else {
                            echo "✅ Secret scan passed!"
                        }
                    } catch (e) {
                        echo "ERROR: Secret scan failed. The scanner command returned an error."
                        error("Failing build due to secret scan failure.")
                    }
                }
            }
        }

        stage('🦠 5. Scan for Malware') {
            steps {
                script {
                    try {
                        echo "Scanning ${IMAGE_NAME} for malware..."
                        def scanJson = sh(
                            script: """
                                docker run --rm --net=host -v /var/run/docker.sock:/var/run/docker.sock:rw \\
                                quay.io/deepfenceio/deepfence_malware_scanner:${SCANNER_VERSION} \\
                                -image-name=${IMAGE_NAME} \\
                                -output json
                            """,
                            returnStdout: true
                        )

                        // --- Malware Report Generation ---
                        def highMalware = 0, mediumMalware = 0, lowMalware = 0
                        if(scanJson) {
                            def data = readJSON(text: scanJson.trim())
                            data.each { finding ->
                                switch(finding.Severity?.toLowerCase()) {
                                    case 'high':   highMalware++; break
                                    case 'medium': mediumMalware++; break
                                    case 'low':    lowMalware++; break
                                }
                            }
                        }
                        def totalMalware = highMalware + mediumMalware + lowMalware

                        echo """
                        +--------------------------------------------------+
                        |             MALWARE SCAN SUMMARY                |
                        +--------------------------------------------------+
                        | Total Malware Found: ${totalMalware.toString().padLeft(28)} |
                        +--------------------------------------------------+
                        ${generateBar('Malware-H', highMalware)}
                        ${generateBar('Malware-M', mediumMalware)}
                        ${generateBar('Malware-L', lowMalware)}
                        +--------------------------------------------------+
                        """

                        // --- Failure Logic ---
                        if (FAIL_ON_HIGH_MALWARE != -1 && highMalware >= FAIL_ON_HIGH_MALWARE) {
                            error("BUILD FAILED: Found ${highMalware} high-severity malware signatures (threshold: ${FAIL_ON_HIGH_MALWARE})")
                        } else {
                            echo "✅ Malware scan passed!"
                        }
                    } catch (e) {
                        echo "ERROR: Malware scan failed. The scanner command returned an error."
                        error("Failing build due to malware scan failure.")
                    }
                }
            }
        }

        stage('🚀 6. Deploy') {
            steps {
                echo "All scans passed! Deploying the application..."
                // Add your deployment commands here.
                // For example: sh "docker run -d -p 5000:5000 ${IMAGE_NAME}"
            }
        }
    }
}
