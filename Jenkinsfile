// Pipeline DevSecOps para SecureDev Tickets
// Código desde el repositorio Git configurado en el job (Pipeline script from SCM)
pipeline {
    agent any

    triggers {
        pollSCM('H/5 * * * *')                      // CI: revisa GitHub cada ~5 min y corre si hay commits nuevos
        cron('''TZ=America/Santiago
H 7 * * 1-5''')                                     // Auditoría diaria (lun-vie ~07:00) aunque nadie toque el código
    }

    options {
        buildDiscarder(logRotator(numToKeepStr: '30'))  // conserva los últimos 30 builds como evidencia
        disableConcurrentBuilds()                       // evita dos despliegues en el mismo puerto
    }

    environment {
        APP_URL = 'http://127.0.0.1:8000'
    }

    stages {
        stage('Checkout') {
            steps {
                sh '''
                    git log -1 --pretty='Commit: %H  Autor: %an  Fecha: %ci  Mensaje: %s'
                    rm -rf reports && mkdir -p reports
                '''
            }
        }

        stage('Build') {
            steps {
                sh '''
                    python3 -m venv .venv
                    .venv/bin/pip install --no-cache-dir --upgrade pip
                    .venv/bin/pip install --no-cache-dir -r requirements-dev.txt
                    .venv/bin/pip freeze > reports/pip-freeze.txt   # versiones exactas instaladas (trazabilidad)
                    cat reports/pip-freeze.txt
                '''
            }
        }

        stage('Test') {
            steps {
                sh '.venv/bin/python -m pytest -q --junitxml=reports/junit.xml'
            }
            post {
                always { junit allowEmptyResults: true, testResults: 'reports/junit.xml' }
            }
        }

        stage('SAST - Bandit') {
            steps {
                catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE') {
                    sh '''
                        bandit -r . -x ./.venv,./test_app.py -f json -o reports/bandit.json || BANDIT_RC=$?
                        bandit -r . -x ./.venv,./test_app.py -f txt  -o reports/bandit.txt  || true
                        cat reports/bandit.txt
                        exit ${BANDIT_RC:-0}
                    '''
                }
            }
        }

        stage('SCA - pip-audit') {
            steps {
                catchError(buildResult: 'FAILURE', stageResult: 'FAILURE') {
                    sh '''
                        set +e
                        pip-audit -r requirements.txt -f json -o reports/pip-audit.json
                        RC=$?
                        pip-audit -r requirements.txt > reports/pip-audit.txt 2>&1
                        cat reports/pip-audit.txt
                        exit $RC
                    '''
                }
            }
        }

        stage('Deploy (staging)') {
            steps {
                sh '''
                    export DATABASE_PATH="$WORKSPACE/staging.db"
                    export SECRET_KEY="staging-$BUILD_NUMBER-$(date +%s)"
                    rm -f "$DATABASE_PATH"

                    # dontKillMe: que Jenkins no apague la app al terminar este paso (la usa ZAP)
                    JENKINS_NODE_COOKIE=dontKillMe nohup .venv/bin/python app.py > reports/app.log 2>&1 &
                    echo $! > app.pid

                    for i in $(seq 1 20); do
                        curl -fs "$APP_URL/health" && break
                        sleep 1
                    done
                    curl -fsS "$APP_URL/health"
                    curl -fsS "$APP_URL/metrics" > reports/metrics.txt
                    grep -q securedev_http_requests_total reports/metrics.txt
                    echo "Staging desplegado en $APP_URL"
                '''
            }
        }

        stage('DAST - OWASP ZAP') {
            steps {
                script {
                    def rc = sh(script: 'zap.sh -cmd -port 8090 -autorun "$WORKSPACE/zap.yaml" > reports/zap.log 2>&1', returnStatus: true)
                    sh 'tail -n 60 reports/zap.log || true'
                    if (rc == 1) { error('ZAP encontró hallazgos de riesgo ALTO (ver reports/zap-report.html)') }
                    if (rc == 2) { unstable('ZAP encontró hallazgos de riesgo MEDIO (ver reports/zap-report.html)') }
                    if (rc > 2)  { error("ZAP terminó con código inesperado: ${rc}") }
                }
            }
        }
    }

    post {
        always {
            sh 'if [ -f app.pid ]; then kill "$(cat app.pid)" 2>/dev/null || true; rm -f app.pid; fi'
            archiveArtifacts artifacts: 'reports/**', allowEmptyArchive: true
        }
        failure  { echo "ALERTA: ${env.JOB_NAME} #${env.BUILD_NUMBER} bloqueado por seguridad: ${env.BUILD_URL}" }
        unstable { echo "AVISO: ${env.JOB_NAME} #${env.BUILD_NUMBER} con hallazgos medios: ${env.BUILD_URL}" }
        success  { echo "OK: ${env.JOB_NAME} #${env.BUILD_NUMBER} listo para producción" }
    }
}
