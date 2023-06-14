pipeline {
    agent any
    
    stages {
       stage("build") {
            steps {
                sh "docker build -t react-jenkins:latest . "
            }
        }   
//         stage('Install Dependencies') {
//             steps {
//                 sh 'npm install'
//             }
//         }
            
//         stage('Deploy') {
//             steps {
//                 // You can customize this step based on your deployment strategy
//                 sh 'npm start'
//                 docker run -itd -p "3000:3000" sptingboot-web:latest 

//             }
//         }
        stage("Run") {
            steps {
                // Run the React development server in a Docker container
                sh "docker ps -a"
                sh 'fuser -k 3000/tcp'             
//                 script {
//                     def portNumber = 3000
//                     def processId = sh(returnStdout: true, script: "lsof -t -i:3000").trim()
//                     sh "kill ${processId}"
//                 }
          sh "docker run -d -p 3000:3000 react-jenkins:latest"
            }
        }
// stage('Cleanup') {
//             steps {
//                 script {
//                     // Kill the running process
//                     try {
//                         sh 'pkill your-process-name'
//                     } catch (Exception e) {
//                         error("Error while killing the process: ${e.getMessage()}")
//                     }
//                 }
//             }
//         }
    }
}
