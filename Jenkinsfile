// ============================================================================
// DEPLOYMENT STRATEGY
// ============================================================================
//   develop branch → build → push to ECR (develop-<sha>)
//   git tag         → build → push to ECR (<tag>)
//
// Image: ecr.alertkick.com/ak/alertkick-mcp
// (Deployment strategy is per-customer / per-AI-client; this pipeline only
// builds + publishes the image. Fleet deploy-service mapping uses
// service_name "mcp" if/when a managed deployment is added.)
// ============================================================================

pipeline {
    agent any

    options {
        buildDiscarder(logRotator(numToKeepStr: '5'))
    }

    triggers {
        githubPush()
    }

    environment {
        GIT_HASH = sh(script: 'git rev-parse --short HEAD', returnStdout: true).trim()
        IMAGE_TAG = "${env.TAG_NAME ?: 'develop-' + GIT_HASH}"
        DOCKER_REPO = "ecr.alertkick.com/ak/alertkick-mcp"
        DOCKER_CREDENTIALS = credentials('docker-login-credentials')
    }

    stages {
        stage('Build Docker Image') {
            steps {
                sh "docker build --build-arg VERSION=${IMAGE_TAG} -t ${DOCKER_REPO}:${IMAGE_TAG} ."
            }
        }

        stage('Push Docker Image') {
            steps {
                withCredentials([usernamePassword(credentialsId: 'docker-login-credentials', usernameVariable: 'DOCKER_USERNAME', passwordVariable: 'DOCKER_PASSWORD')]) {
                    sh """
                        DOCKER_CFG=\$(mktemp -d)
                        echo \$DOCKER_PASSWORD | docker --config \$DOCKER_CFG login https://ecr.alertkick.com -u \$DOCKER_USERNAME --password-stdin
                        docker --config \$DOCKER_CFG push ${DOCKER_REPO}:${IMAGE_TAG}
                        docker tag ${DOCKER_REPO}:${IMAGE_TAG} ${DOCKER_REPO}:latest
                        docker --config \$DOCKER_CFG push ${DOCKER_REPO}:latest
                        rm -rf \$DOCKER_CFG
                    """
                }
            }
        }
    }

    post {
        always {
            cleanWs()
        }
    }
}
