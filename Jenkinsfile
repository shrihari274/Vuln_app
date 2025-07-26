pipeline {
    agent any

    environment {
        // Image to build and scan
        IMAGE_NAME = "vuln-flask-app:${BUILD_NUMBER}"

        // Deepfence scanner settings
        SCANNER_VERSION = '2.5.2'
        DEEPFENCE_CONSOLE_URL = 'https://192.168.74.125'  // Use full URL with https
        DEEPFENCE_PRODUCT = 'ThreatMapper'
        DEEPFENCE_LICENSE = '26545419-e7a1-44e8-b6a7-f853e68499c3'  // Must be valid license

        // Thresholds (set high if you don’t want to fail the pipeline)
        FAIL_CVE_COUNT = 10000000
        FAIL_CRITICAL_CVE_COUNT = 10000
        FAIL_HIGH_CVE_COUNT = 5000000
        FAIL_MEDIUM_CVE_COUNT = 100000
        FAIL_LOW_CVE_COUNT = 200000
        FAIL_CVE_SCORE = 800000
    }

    stages {
        stage('1. Checkout Code') {
            steps {
                checkout scm
            }
        }

        stage('2. Build Docker Image') {
            steps {
                script {
                    echo "🏗️ Building image: ${IMAGE_NAME}"
                    sh "docker build -t ${IMAGE_NAME} ."
                }
            }
        }

        stage('3. Scan with ThreatMapper CLI') {
            steps {
                script {
                    withCredentials([string(credentialsId: 'deepfence_api_key', variable: 'DEEPFENCE_API_KEY')]) {
                        echo "🔍 Starting scan for image: ${IMAGE_NAME}"

                        // Run the scanner as Docker container inside Jenkins
                        sh """
                            docker run --rm --net=host \
                            -v /var/run/docker.sock:/var/run/docker.sock \
                            quay.io/deepfenceio/deepfence_package_scanner_cli:${SCANNER_VERSION} \
                            -console-url=${DEEPFENCE_CONSOLE_URL} \
                            -deepfence-key=${DEEPFENCE_API_KEY} \
                            -license=${DEEPFENCE_LICENSE} \
                            -product=${DEEPFENCE_PRODUCT} \
                            -source=${IMAGE_NAME} \
                            -fail-on-count=${FAIL_CVE_COUNT} \
                            -fail-on-critical-count=${FAIL_CRITICAL_CVE_COUNT} \
                            -fail-on-high-count=${FAIL_HIGH_CVE_COUNT} \
                            -fail-on-medium-count=${FAIL_MEDIUM_CVE_COUNT} \
                            -fail-on-low-count=${FAIL_LOW_CVE_COUNT} \
                            -fail-on-score=${FAIL_CVE_SCORE}
                        """
                    }
                }
            }
        }

        stage('4. Deploy Application') {
            when {
                expression { currentBuild.result == null || currentBuild.result == 'SUCCESS' }
            }
            steps {
                echo "🚀 Deploying ${IMAGE_NAME} as scan passed!"
                // Replace with your deployment command
                // sh "docker run -d -p 5000:5000 ${IMAGE_NAME}"
            }
        }
    }

    post {
        always {
            echo "🧹 Cleaning up..."
        }
        success {
            echo "✅ Pipeline Success!"
        }
        failure {
            echo "❌ Pipeline Failed!"
        }
    }
}
