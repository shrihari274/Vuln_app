pipeline {
    agent any // Run on any available Jenkins agent

    environment {
        // --- General Configuration ---
        IMAGE_NAME            = "vuln-flask-app:${BUILD_NUMBER}"
        DEEPFENCE_CONSOLE_URL = '192.168.74.125'
        SCANNER_VERSION       = '2.5.2'
        DEEPFENCE_PRODUCT     = 'ThreatMapper'

        // --- Vulnerability Failure Conditions (from the official example) ---
        FAIL_ON_CRITICAL_VULNS = 1
        FAIL_ON_HIGH_VULNS     = 5
        FAIL_ON_MEDIUM_VULNS   = 10
        FAIL_ON_LOW_VULNS      = 20
        
        // --- Secrets & Malware Failure Conditions ---
        FAIL_ON_HIGH_SECRETS   = 1
        FAIL_ON_HIGH_MALWARE   = 1
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
                    echo "Scanning ${IMAGE_NAME} for vulnerabilities..."
                    // Securely load BOTH the API key and the License key
                    withCredentials([
                        string(credentialsId: 'deepfence-api-key', variable: 'DF_API_KEY'),
                        string(credentialsId: 'deepfence-license-key', variable: 'DF_LICENSE_KEY')
                    ]) {
                        // The sh step now includes -license and -product parameters
                        sh '''
                            docker run --rm --net=host -v /var/run/docker.sock:/var/run/docker.sock:rw \
                            quay.io/deepfenceio/deepfence_package_scanner_cli:${SCANNER_VERSION} \
                            -console-url="${DEEPFENCE_CONSOLE_URL}" \
                            -deepfence-key="${DF_API_KEY}" \
                            -license="${DF_LICENSE_KEY}" \
                            -product="${DEEPFENCE_PRODUCT}" \
                            -source="${IMAGE_NAME}" \
                            -scan-type="base,java,python,ruby,php,nodejs,js" \
                            -fail-on-critical-count="${FAIL_ON_CRITICAL_VULNS}" \
                            -fail-on-high-count="${FAIL_ON_HIGH_VULNS}" \
                            -fail-on-medium-count="${FAIL_ON_MEDIUM_VULNS}" \
                            -fail-on-low-count="${FAIL_ON_LOW_VULNS}"
                        '''
                    }
                }
            }
        }

        stage('🤫 4. Scan for Secrets') {
            steps {
                echo "Scanning ${IMAGE_NAME} for secrets..."
                sh '''
                    docker run --rm --net=host -v /var/run/docker.sock:/var/run/docker.sock:rw \
                    quay.io/deepfenceio/deepfence_secret_scanner:${SCANNER_VERSION} \
                    -image-name="${IMAGE_NAME}" \
                    -fail-on-high-count="${FAIL_ON_HIGH_SECRETS}"
                '''
            }
        }

        stage('🦠 5. Scan for Malware') {
            steps {
                echo "Scanning ${IMAGE_NAME} for malware..."
                sh '''
                    docker run --rm --net=host -v /var/run/docker.sock:/var/run/docker.sock:rw \
                    quay.io/deepfenceio/deepfence_malware_scanner:${SCANNER_VERSION} \
                    -image-name="${IMAGE_NAME}" \
                    -fail-on-high-count="${FAIL_ON_HIGH_MALWARE}"
                '''
            }
        }

        stage('🚀 6. Deploy') {
            steps {
                echo "✅ All scans passed! Deploying the application..."
                // Example deployment:
                // sh "docker run -d -p 5000:5000 ${IMAGE_NAME}"
            }
        }
    }
}
