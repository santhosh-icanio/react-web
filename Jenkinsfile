pipeline {
    agent any
    
    stages {
        stage('Build') {
            steps {
                sh "npm install"
               // sh "pm2 stop react"
                sh "pm2 start --name react  npm -- start"
                sh "sleep 10"
                sh "pm2 list"
            }
        }
    }
    }
