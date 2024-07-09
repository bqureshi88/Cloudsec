pipeline {
    agent any

    environment {
        AZURE_CREDENTIALS = credentials('azure-credentials-id')
    }

    stages {
        stage('Checkout') {
            steps {
                git 'https://github.com/your-org/sample-app.git'
            }
        }
        stage('Build') {
            steps {
                sh 'mvn clean install'
            }
        }
        stage('Test') {
            steps {
                sh 'mvn test'
            }
        }
        stage('Security Scan') {
            steps {
                sh 'mvn dependency-check:check'
            }
        }
        stage('Deploy') {
            steps {
                script {
                    withCredentials([azureServicePrincipal(
                        credentialsId: 'AZURE_CREDENTIALS',
                        subscriptionIdVariable: 'SUBSCRIPTION_ID',
                        clientIdVariable: 'CLIENT_ID',
                        clientSecretVariable: 'CLIENT_SECRET',
                        tenantIdVariable: 'TENANT_ID'
                    )]) {
                        sh """
                            az login --service-principal -u $CLIENT_ID -p $CLIENT_SECRET --tenant $TENANT_ID
                            az webapp deployment source config-zip --resource-group your-resource-group --name your-webapp-name --src target/sample-app.zip
                        """
                    }
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
