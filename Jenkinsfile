// Pipeline DevSecOps para SecureDev Tickets
// Toma el código desde /proyecto (carpeta montada en el contenedor Jenkins)
pipeline {
    agent any

    stages {
        stage('Preparar workspace') {
            steps {
                // Jenkins ya hizo checkout del repo (Pipeline script from SCM)
                sh '''
                    git log -1 --pretty='Commit: %H  Autor: %an  Mensaje: %s'
                    rm -rf reports && mkdir -p reports
                    ls -la
                '''
            }
        }
        
        stage('Obtener código') {
            steps {
                deleteDir()
                sh '''
                    tar -C /proyecto --exclude=.venv --exclude=__pycache__ --exclude='*.db' -cf - . | tar -xf -
                    mkdir -p reports
                    ls -la
                '''
            }
        }

        stage('Preparar entorno Python') {
            steps {
                sh '''
                    python3 -m venv .venv
                    .venv/bin/pip install --no-cache-dir -r requirements.txt
                '''
            }
        }

        stage('SAST - Bandit') {
            steps {
                catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE') {
                    sh '''
                        bandit -r . -x ./.venv -f json -o reports/bandit.json || BANDIT_RC=$?
                        bandit -r . -x ./.venv -f txt  -o reports/bandit.txt  || true
                        cat reports/bandit.txt
                        exit ${BANDIT_RC:-0}
                    '''
                }
            }
        }

        stage('SCA - pip-audit') {
            steps {
                catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE') {
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

        stage('Prueba de humo') {
            steps {
                sh '''
                    export DATABASE_PATH="$WORKSPACE/test.db"
                    export SECRET_KEY="clave-solo-pipeline"
                    .venv/bin/python app.py > reports/app.log 2>&1 &
                    APP_PID=$!
                    trap 'kill $APP_PID 2>/dev/null || true' EXIT

                    for i in $(seq 1 20); do
                        curl -fs http://127.0.0.1:8000/health && break
                        sleep 1
                    done
                    curl -fs http://127.0.0.1:8000/health
                    curl -fs http://127.0.0.1:8000/metrics > reports/metrics.txt
                    grep -q securedev_http_requests_total reports/metrics.txt
                    echo "App OK: /health y /metrics responden"
                '''
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'reports/**', allowEmptyArchive: true
        }
    }
}
