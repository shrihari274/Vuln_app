pipeline {
    agent any // Run on any available Jenkins agent

    environment {
        // --- Configuration ---
        // Your application's image name
        IMAGE_NAME = "vuln-flask-app:${BUILD_NUMBER}"
        // ThreatMapper console details
        DEEPFENCE_CONSOLE_URL = '192.168.74.125'
        // DEEPFENCE_KEY has been removed and will be injected from Jenkins Credentials
        SCANNER_VERSION = '2.5.2'

        // --- Failure Conditions (set to -1 to ignore a check) ---
        // Vulnerability Scan
        FAIL_ON_CRITICAL_VULNERABILITIES = 1
        FAIL_ON_HIGH_VULNERABILITIES = 5
        // Secret Scan
        FAIL_ON_HIGH_SECRETS = 1
        // Malware Scan
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
                sh "docker build -t ${IMAGE_NAME} ${pwd()}"
            }
        }

        stage('🛡️ 3. Scan for Vulnerabilities') {
            steps {
                script {
                    echo "Scanning ${IMAGE_NAME} for vulnerabilities..."
                    try {
                        // Securely inject the API key from Jenkins Credentials
                        withCredentials() {
                            sh """
                                docker run --rm --net=host -v /var/run/docker.sock:/var/run/docker.sock:rw \
                                quay.io/deepfenceio/deepfence_package_scanner_cli:${SCANNER_VERSION} \
                                -console-url=${DEEPFENCE_CONSOLE_URL} -deepfence-key=${DEEPFENCE_API_KEY_FROM_CREDS} \
                                -source=${IMAGE_NAME} -scan-type=base,java,python,ruby,php,nodejs,js \
                                -fail-on-critical-count=${FAIL_ON_CRITICAL_VULNERABILITIES} \
                                -fail-on-high-count=${FAIL_ON_HIGH_VULNERABILITIES}
                            """
                        }
                    } catch (Exception err) {
                        // The sh command will fail if scan conditions are met, this catches it
                        currentBuild.result = 'FAILURE'
                        error("Vulnerability scan failed. Check logs for details.")
                    }
                }
            }
        }

        stage('🤫 4. Scan for Secrets') {
            steps {
                script {
                    echo "Scanning ${IMAGE_NAME} for secrets..."
                     try {
                        sh """
                            docker run --rm --net=host -v /var/run/docker.sock:/var/run/docker.sock:rw \
                            quay.io/deepfenceio/deepfence_secret_scanner:${SCANNER_VERSION} \
                            -image-name=${IMAGE_NAME} \
                            -fail-on-high-count=${FAIL_ON_HIGH_SECRETS}
                        """
                    } catch (Exception err) {
                        currentBuild.result = 'FAILURE'
                        error("Secret scan failed. Check logs for details.")
                    }
                }
            }
        }

        stage('🦠 5. Scan for Malware') {
            steps {
                script {
                    echo "Scanning ${IMAGE_NAME} for malware..."
                     try {
                        sh """
                            docker run --rm --net=host -v /var/run/docker.sock:/var/run/docker.sock:rw \
                            quay.io/deepfenceio/deepfence_malware_scanner:${SCANNER_VERSION} \
                            -image-name=${IMAGE_NAME} \
                            -fail-on-high-count=${FAIL_ON_HIGH_MALWARE}
                        """
                    } catch (Exception err) {
                        currentBuild.result = 'FAILURE'
                        error("Malware scan failed. Check logs for details.")
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
