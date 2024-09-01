from fabric import Connection

def deploy():
    # Establish SSH connection
    conn = Connection('user@remote-server.com')
    
    # Run commands on the remote server
    conn.run('cd /path/to/project && git pull')
    conn.run('pip install -r requirements.txt')
    conn.run('systemctl restart myapp')

    print("Deployment completed successfully!")
