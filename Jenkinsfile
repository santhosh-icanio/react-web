pipeline {
    agent any
    
    stages {
        stage('Build') {
            steps {
                sh "pm2 stop react"
                sh "pm2 start --name react  npm -- start"
            }
        }
    }
    }
