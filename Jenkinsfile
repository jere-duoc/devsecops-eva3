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
                // 1) Sesión autenticada para ZAP: login con token CSRF, igual que un navegador
                sh '''
                    rm -f zap-cookies.txt zap-session.txt
                    TOKEN=$(curl -fsS -c zap-cookies.txt -b zap-cookies.txt "$APP_URL/login" \
                            | sed -n 's/.*name="csrf_token" value="\\([^"]*\\)".*/\\1/p' | head -1)
                    test -n "$TOKEN"
                    curl -fsS -o /dev/null -c zap-cookies.txt -b zap-cookies.txt \
                         --data-urlencode "username=ana" --data-urlencode "password=ana123" \
                         --data-urlencode "csrf_token=$TOKEN" "$APP_URL/login"
                    curl -fsS -o /dev/null -c zap-cookies.txt -b zap-cookies.txt "$APP_URL/"   # genera el token CSRF de la sesión
                    SESSION=$(awk '$6 == "session" {print $7}' zap-cookies.txt | tail -1)
                    test -n "$SESSION"
                    echo "session=$SESSION" > zap-session.txt
                    echo "Sesión de prueba creada para ZAP (usuario ana)"
                '''
                script {
                    // 2) ZAP agrega esa cookie de sesión a todas sus peticiones
                    def rc = sh(script: '''
                        export ZAP_AUTH_HEADER=Cookie
                        export ZAP_AUTH_HEADER_VALUE="$(cat zap-session.txt)"
                        zap.sh -cmd -port 8090 -autorun "$WORKSPACE/zap.yaml" > reports/zap.log 2>&1
                    ''', returnStatus: true)
                    sh 'tail -n 60 reports/zap.log || true'

                    // 3) Control de calidad: si ZAP no llegó a las páginas protegidas, el escaneo no sirve
                    def auth = sh(script: 'grep -Eq "GET /tickets/1 HTTP/1.1\\" 200" reports/app.log', returnStatus: true)
                    if (auth != 0) { error('ZAP no logró escanear las rutas autenticadas: resultado no confiable') }
                    echo 'ZAP escaneó rutas autenticadas (/tickets/1 respondió 200)'
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
            sh 'rm -f zap-cookies.txt zap-session.txt'   // no dejar la sesión de prueba en el workspace
            archiveArtifacts artifacts: 'reports/**', allowEmptyArchive: true
        }
        failure  { echo "ALERTA: ${env.JOB_NAME} #${env.BUILD_NUMBER} bloqueado por seguridad: ${env.BUILD_URL}" }
        unstable { echo "AVISO: ${env.JOB_NAME} #${env.BUILD_NUMBER} con hallazgos medios: ${env.BUILD_URL}" }
        success  { echo "OK: ${env.JOB_NAME} #${env.BUILD_NUMBER} listo para producción" }
    }
}
