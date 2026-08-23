pipeline {
    agent any

    stages {

        stage('Checkout') {
            steps {
                echo 'Repository checkout successful'
            }
        }

        stage('SonarQube Scan') {
            steps {
                echo 'Starting SonarQube analysis'

                script {
                    def scannerHome = tool name: 'SonarQube Scanner',
                        type: 'hudson.plugins.sonar.SonarRunnerInstallation'

                    withSonarQubeEnv('SonarQube') {
                        sh """
                            ${scannerHome}/bin/sonar-scanner \
                              -Dsonar.projectKey=security-test \
                              -Dsonar.projectName=Security-Test \
                              -Dsonar.sources=.
                        """
                    }
                }
            }
        }

        stage('Trivy Scan') {
            steps {
                echo 'Starting Trivy security scan'

                sh '''
                    /var/jenkins_home/tools/trivy/trivy fs \
                      --scanners vuln,secret \
                      --format json \
                      --output trivy-report.json \
                      .
                '''
            }
        }

        stage('AI-Based Analysis (Generative AI + ML Risk Model)') {
            steps {
                echo 'Starting Gemini generative-AI analysis and dataset-driven ML risk scoring'

                withCredentials([
                    string(
                        credentialsId: 'gemini-api-key',
                        variable: 'GEMINI_API_KEY'
                    )
                ]) {
                    sh '''
                        pip install --break-system-packages -q -r requirements.txt
                        test -f ml_model/model.pkl || python3 ml_model/train_model.py
                        python3 ai_security_analyzer.py
                    '''
                }
            }
        }

        stage('Security Gate') {
            steps {
                echo 'Checking security gate'

                sh '''
                    python3 - <<'PY'
import json
import sys

with open("trivy-report.json", "r", encoding="utf-8") as f:
    report = json.load(f)

critical = 0
high = 0
medium = 0
low = 0
secrets = 0

for result in report.get("Results", []):
    for vuln in result.get("Vulnerabilities", []) or []:
        severity = vuln.get("Severity", "").upper()
        if severity == "CRITICAL": critical += 1
        elif severity == "HIGH": high += 1
        elif severity == "MEDIUM": medium += 1
        elif severity == "LOW": low += 1

    for secret in result.get("Secrets", []) or []:
        secrets += 1
        severity = secret.get("Severity", "").upper()
        if severity == "CRITICAL": critical += 1
        elif severity == "HIGH": high += 1
        elif severity == "MEDIUM": medium += 1
        elif severity == "LOW": low += 1

print("")
print("========== SECURITY GATE ==========")
print(f"CRITICAL findings: {critical}")
print(f"HIGH findings:     {high}")
print(f"MEDIUM findings:   {medium}")
print(f"LOW findings:      {low}")
print(f"SECRETS detected:  {secrets}")

if critical > 0 or high > 0:
    print("Security Gate: FAILED")
    print("Deployment:    BLOCKED")
    print("CRITICAL or HIGH security findings detected. Failing pipeline.")
    sys.exit(1)

print("Security Gate: PASSED")
print("Deployment:    ALLOWED")
print("No CRITICAL or HIGH findings detected. Proceeding with deployment.")
PY
                '''
            }
        }

        stage('Automated Deployment') {
            steps {
                echo 'Building Docker images for the dashboard and the demo e-commerce app'
                sh '''
                    docker build -t intelligent-security-dashboard:latest -f Dockerfile.dashboard .
                    docker build -t securecart-demo:latest ./demo_app
                '''
                echo 'Deploying via docker-compose (secure, reproducible deployment)'
                sh 'docker compose up -d'
            }
        }

        stage('Feedback Loop: Retrain ML Model') {
            steps {
                echo 'Folding this run''s scan results back into the dataset-driven risk model'
                sh 'python3 feedback/retrain.py'
            }
        }

        stage('Monitor and Improve') {
            steps {
                echo 'Scan outcome and updated model metrics recorded to monitor/history.db'
                echo 'View trends at: http://<host>:5000/monitor'
            }
        }
    }

    post {
        failure {
            echo 'Pipeline failed - see Security Gate stage output above for blocking findings.'
        }
    }
}