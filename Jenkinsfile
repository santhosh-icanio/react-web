pipeline {
    agent any

        stage("Run") {
            steps {
                sh "pm2 stop react"
                sh " pm2 start --name react  npm -- start"
            }
        }
    
}
