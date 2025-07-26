pipeline {
    agent any
    
    environment {
        // Image configuration
        IMAGE_NAME = "vuln-flask-app:${BUILD_NUMBER}"
        
        // Deepfence configuration
        DEEPFENCE_CONSOLE_URL = '192.168.74.125'  // Management console URL
        SCANNER_VERSION = '2.5.2'                 // Deepfence scanner version
        DEEPFENCE_PRODUCT = 'ThreatMapper'        // Product name
        DEEPFENCE_LICENSE = '26545419-e7a1-44e8-b6a7-f853e68499c3' // License key
        
        // Vulnerability thresholds
        FAIL_CVE_COUNT = 10000000          // Total vulnerabilities
        FAIL_CRITICAL_CVE_COUNT = 10000   // Critical vulnerabilities
        FAIL_HIGH_CVE_COUNT = 5000000       // High vulnerabilities
        FAIL_MEDIUM_CVE_COUNT = 100000    // Medium vulnerabilities
        FAIL_LOW_CVE_COUNT = 200000       // Low vulnerabilities
        FAIL_CVE_SCORE = 800000            // Cumulative CVE score
    }

    stages {
        stage('1. Clone Repository') {
            steps {
                checkout scm
            }
        }

        stage('2. Build Docker Image') {
            steps {
                script {
                    echo "Building Docker image: ${IMAGE_NAME}"
                    sh "docker build -t ${IMAGE_NAME} ."
                }
            }
        }

        stage('3. Run Deepfence Vulnerability Scan') {
            steps {
                script {
                    withCredentials([string(credentialsId: 'deepfence_api_key', variable: 'DEEPFENCE_API_KEY')]) {
                        try {
                            echo "Scanning ${IMAGE_NAME} for vulnerabilities..."
                            sh """
                                docker run --rm -it --net=host --privileged \
                                -v /var/run/docker.sock:/var/run/docker.sock:rw \
                                quay.io/deepfenceio/deepfence_package_scanner_cli:${SCANNER_VERSION} \
                                -deepfence-key=${DEEPFENCE_API_KEY} \
                                -console-url=${DEEPFENCE_CONSOLE_URL} \
                                -product=${DEEPFENCE_PRODUCT} \
                                -license=${DEEPFENCE_LICENSE} \
                                -source=${IMAGE_NAME} \
                                -fail-on-count=${FAIL_CVE_COUNT} \
                                -fail-on-critical-count=${FAIL_CRITICAL_CVE_COUNT} \
                                -fail-on-high-count=${FAIL_HIGH_CVE_COUNT} \
                                -fail-on-medium-count=${FAIL_MEDIUM_CVE_COUNT} \
                                -fail-on-low-count=${FAIL_LOW_CVE_COUNT} \
                                -fail-on-score=${FAIL_CVE_SCORE}
                            """
                        } catch (Exception err) {
                            currentBuild.result = 'FAILURE'
                            error("❌ Vulnerability scan failed. Check logs for details.")
                        }
                    }
                }
            }
        }

        stage('4. Deploy Application') {
            when {
                expression { currentBuild.result == null || currentBuild.result == 'SUCCESS' }
            }
            steps {
                echo "✅ All scans passed! Deploying the application..."
                // Add your deployment commands here
                // Example:
                // sh "docker run -d -p 5000:5000 --name vuln-app ${IMAGE_NAME}"
            }
        }
    }

    post {
        always {
            echo "Cleaning up workspace..."
            // Add any cleanup steps here
        }
        failure {
            echo "Pipeline failed! Check logs for details."
        }
        success {
            echo "Pipeline completed successfully!"
        }
    }
}
