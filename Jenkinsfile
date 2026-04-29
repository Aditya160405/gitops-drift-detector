pipeline {
  agent any

  parameters {
    choice(
      name: 'ACTION',
      choices: ['deploy', 'destroy'],
      description: 'deploy = provision + run app   |   destroy = tear everything down'
    )
    string(
      name: 'AWS_REGION',
      defaultValue: 'ap-south-1',
      description: 'AWS region'
    )
  }

  environment {
    TF_DIR             = 'terraform'
    AWS_DEFAULT_REGION = "${params.AWS_REGION}"
  }

  options {
    timestamps()
    timeout(time: 30, unit: 'MINUTES')
    ansiColor('xterm')
  }

  stages {

    stage('Checkout') {
      steps {
        checkout scm
        sh 'ls -la'
      }
    }

    stage('Terraform Init') {
      steps {
        withCredentials([[$class: 'AmazonWebServicesCredentialsBinding', credentialsId: 'aws-creds']]) {
          dir("${TF_DIR}") {
            sh 'terraform init -input=false'
          }
        }
      }
    }

    stage('Terraform Apply') {
      when { expression { params.ACTION == 'deploy' } }
      steps {
        withCredentials([
          [$class: 'AmazonWebServicesCredentialsBinding', credentialsId: 'aws-creds'],
          sshUserPrivateKey(credentialsId: 'ec2-ssh-key', keyFileVariable: 'SSH_KEY')
        ]) {
          dir("${TF_DIR}") {
            sh '''
              set -e
              chmod 600 "$SSH_KEY"
              PUBKEY=$(ssh-keygen -y -f "$SSH_KEY")
              terraform apply -auto-approve \
                -var "ssh_public_key=$PUBKEY"
              terraform output -raw app_public_ip > ../app_ip.txt
              echo "Public IP: $(cat ../app_ip.txt)"
            '''
          }
        }
      }
    }

    stage('Wait for SSH') {
      when { expression { params.ACTION == 'deploy' } }
      steps {
        sh '''
          set -e
          IP=$(cat app_ip.txt)
          echo "Waiting for SSH on $IP ..."
          for i in $(seq 1 30); do
            if nc -z -w 3 "$IP" 22; then
              echo "SSH reachable on attempt $i"
              exit 0
            fi
            sleep 10
          done
          echo "SSH not reachable after 5 minutes" >&2
          exit 1
        '''
      }
    }

    stage('Ansible Deploy') {
      when { expression { params.ACTION == 'deploy' } }
      steps {
        withCredentials([sshUserPrivateKey(credentialsId: 'ec2-ssh-key', keyFileVariable: 'SSH_KEY')]) {
          sh '''
            set -e
            IP=$(cat app_ip.txt)
            chmod 600 "$SSH_KEY"

            cat > inventory.ini <<EOF
[drift_app]
$IP ansible_user=ec2-user ansible_ssh_private_key_file=$SSH_KEY ansible_ssh_common_args='-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null'
EOF

            ansible-playbook -i inventory.ini ansible/deploy_app.yml
          '''
        }
      }
    }

    stage('Smoke Test') {
      when { expression { params.ACTION == 'deploy' } }
      steps {
        sh '''
          set -e
          IP=$(cat app_ip.txt)
          echo "Hitting http://$IP:8080/ ..."
          for i in $(seq 1 10); do
            if curl -fsS "http://$IP:8080/" > /dev/null; then
              echo "✅ Dashboard responding"
              exit 0
            fi
            sleep 5
          done
          echo "Dashboard didn't respond" >&2
          exit 1
        '''
      }
    }

    stage('Terraform Destroy') {
      when { expression { params.ACTION == 'destroy' } }
      steps {
        withCredentials([
          [$class: 'AmazonWebServicesCredentialsBinding', credentialsId: 'aws-creds'],
          sshUserPrivateKey(credentialsId: 'ec2-ssh-key', keyFileVariable: 'SSH_KEY')
        ]) {
          dir("${TF_DIR}") {
            sh '''
              set -e
              chmod 600 "$SSH_KEY"
              PUBKEY=$(ssh-keygen -y -f "$SSH_KEY")
              terraform destroy -auto-approve \
                -var "ssh_public_key=$PUBKEY"
            '''
          }
        }
      }
    }
  }

  post {
    success {
      script {
        if (params.ACTION == 'deploy' && fileExists('app_ip.txt')) {
          def ip = readFile('app_ip.txt').trim()
          echo "🚀 DriftWatch live at: http://${ip}:8080"
          echo "   SSH: ssh -i <key> ec2-user@${ip}"
        } else if (params.ACTION == 'destroy') {
          echo "🧹 Infrastructure destroyed."
        }
      }
    }
    failure {
      echo "❌ Pipeline failed — check the stage logs above."
    }
    always {
      sh 'rm -f inventory.ini || true'
    }
  }
}