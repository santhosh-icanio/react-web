pipeline {
    agent any
    
    stages {
        stage('Build') {
            steps {
                sh "npm install"
                sh "pm2 delete react" 
                sh "pm2 start --name react  npm -- start"
            }
        }
    }
    }
