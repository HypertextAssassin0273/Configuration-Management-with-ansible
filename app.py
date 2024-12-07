## DEPENDENCIES ##
from flask import Flask, render_template, request, jsonify, session # external
from werkzeug.security import generate_password_hash # built-in
from flask_session import Session # external
from logging.handlers import RotatingFileHandler

import os, shutil, signal, atexit, json, yaml, logging, tempfile # built-in
import docker, ansible_runner # external


## GLOBAL CONFIGURATION ##
app = Flask(__name__) # create a Flask app
app.config['SECRET_KEY'] = os.urandom(24) # set a secret key for session management
app.config['SESSION_TYPE'] = 'filesystem' # store session data in 'filesystem'

def clear_session_files(dir = 'flask_session'):
    if os.path.exists(dir):
        shutil.rmtree(dir) # removes the directory and its contents
        app.logger.info("Cleared old Flask session files at startup.")

clear_session_files() # clear old session files at startup
Session(app) # initialize session management

client = docker.from_env() # connect to docker daemon (using default socket)
logging.basicConfig(level=logging.DEBUG) # set logging level to DEBUG (for app.logger)

ssh_key_dir = os.path.expanduser("~/.ssh")
ssh_key_path = os.path.join(ssh_key_dir, "docker_container_key")
public_key_path = ssh_key_path + ".pub"

MAX_CONTAINER_LIMIT = 100 # maximum number of containers that can be spawned


## LOGGING SETUP ##

# Set up logging
log_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

# Create a file handler for logging to a file (overwrite the file each time)
log_file = "app.log"  # The log file name
file_handler = logging.FileHandler(log_file, mode='w')  # 'w' mode will overwrite the file each time
file_handler.setFormatter(log_formatter)
file_handler.setLevel(logging.DEBUG)  # Adjust the level as needed (DEBUG, INFO, WARNING, ERROR, CRITICAL)

# Create a console handler for logging to the terminal
console_handler = logging.StreamHandler()
console_handler.setFormatter(log_formatter)
console_handler.setLevel(logging.DEBUG)  # Adjust the level as needed

# Get the app logger and set the log level
app.logger.setLevel(logging.DEBUG)
app.logger.addHandler(file_handler)
app.logger.addHandler(console_handler)

# Log a message to verify setup
app.logger.info("Logging setup complete. Logs will be saved to 'app.log' and displayed on the console.")


## HELPER FUNCTIONS ##
def ensure_ssh_key():
    """
    Ensures the presence of an SSH key pair for secure container access.
    If the key doesn't exist, it is generated automatically.
    """
    os.makedirs(ssh_key_dir, exist_ok=True) # ensure .ssh directory exists

    if not os.path.exists(ssh_key_path) or not os.path.exists(public_key_path):
        app.logger.info("Generating new SSH key pair...")
        cmd = f"ssh-keygen -t rsa -b 4096 -f {ssh_key_path} -N ''"

        if os.system(cmd) != 0:
            raise RuntimeError("SSH key pair generation failed.")
        
        os.chmod(ssh_key_path, 0o600)  # ensure private key is secure

    with open(public_key_path, "r") as key_file:
        return key_file.read().strip()


def spawn_container(public_key):
    try:
        container = client.containers.run(
            'debian:bullseye-slim',
            command = f'/bin/bash -c "\
                        apt-get update && \
                        apt-get install -y openssh-server python3 && \
                        mkdir -p /run/sshd && \
                        mkdir -p /root/.ssh && \
                        echo \'{public_key}\' > /root/.ssh/authorized_keys && \
                        chmod 600 /root/.ssh/authorized_keys && \
                        chmod 700 /root/.ssh && \
                        sed -i \'s/#PermitRootLogin prohibit-password/PermitRootLogin yes/\' /etc/ssh/sshd_config && \
                        sed -i \'s/#PubkeyAuthentication yes/PubkeyAuthentication yes/\' /etc/ssh/sshd_config && \
                        sed -i \'s@#PasswordAuthentication yes@PasswordAuthentication no@\' /etc/ssh/sshd_config && \
                        exec /usr/sbin/sshd -D"',
            detach = True,
            ports = {'22/tcp': None}, # assign random host port
            tty = True,
            labels = {"flask_app": "spawned_container"} # custom label for faster lookup
        )

        app.logger.info(f"Container {container.id[:12]} spawned successfully.")
        return container

    except Exception as e:
        app.logger.error(f"Error spawning container: {str(e)}")
        raise


def get_port_mapping(container):
    """
    Returns the host port mapping for a given container.
    """
    container.reload() # refresh container status
    ports = container.attrs['NetworkSettings']['Ports']
    return None if '22/tcp' not in ports else ports['22/tcp'][0]['HostPort']


def create_temp_file(content, suffix, writer=lambda content, file: file.write(content)):
    """
    Creates a secure temporary file with the specified content and suffix.
    """
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix=suffix) as temp_file:
        os.chmod(temp_file.name, 0o600) # secure file
        writer(content, temp_file) # write file contents (using provided function)
        return temp_file.name


def parse_ansible_results(result):
    """
    Parses Ansible results from a given AnsibleRunner object.
    """
    results = {}

    for host_event in result.events:
        if host_event['event'] == 'runner_on_ok':
            event_data = host_event.get('event_data', {}) # host_event['event_data']
            event_result = event_data.get('res', {})      # event_data['res']

            if 'stdout' in event_result:
                results[event_data['host']] = event_result['stdout']

    return results 


def cleanup_files(file_paths):
    """
    Removes temporary files created during the application lifecycle.
    """
    for file_path in file_paths:
        if os.path.exists(file_path):
            os.unlink(file_path) # removes the file


def run_ansible(hosts, command):
    """
    Runs an Ansible playbook on specified hosts with a given command.
    """
    try:
        inventory = {
            "all": {
                "hosts": hosts
            }
        }
        inventory_file_path = create_temp_file(
            content = inventory,
            suffix = '.json',
            writer = json.dump
        )

        playbook_content = f'''
        - name: Run custom command on all hosts
          hosts: all
          tasks:
            - name: Execute custom command
              shell: {command}
              register: command_output
            - debug:
                var: command_output.stdout
        '''
        playbook_file_path = create_temp_file(
            content = playbook_content,
            suffix = '.yml'
        )

        app.logger.info(f"Running Ansible playbook on hosts: {hosts}")
        result = ansible_runner.run(
            private_data_dir = tempfile.gettempdir(), # set platform-independent '/tmp' directory
            playbook = playbook_file_path,
            inventory = inventory_file_path,
            extravars = {'ansible_ssh_private_key_file': ssh_key_path}
        )

        return parse_ansible_results(result)

    except Exception as e:
        app.logger.error(f"Error running Ansible: {str(e)}")
        raise

    finally:
        cleanup_files([inventory_file_path, playbook_file_path])


def remove_or_stop_containers(containers, action, type='spawned'):
    """
    Stops or removes the specified containers based on the action parameter.
    """
    for container in containers:
        try:
            container.stop()
            if action == 'remove':
                container.remove()
            app.logger.info(f"{type} container {container.id[:12]} {'removed' if action == 'remove' else 'stopped'}")

        except Exception as e:
            app.logger.warning(f"Failed to {action} {type} container {container.id[:12]}: {str(e)}")


def cleanup(action='stop'):
    """Cleans up all spawned containers and orphaned containers (by stopping or removing them)."""    
    if action == 'remove':
        containers = client.containers.list(all=True, filters={"label": "flask_app=spawned_container"})
        remove_or_stop_containers(containers, 'remove')

        # remove all orphaned containers (if any, due to previous errors)
        containers = client.containers.list(all=True, filters={"ancestor": "debian:bullseye-slim"})
        remove_or_stop_containers(containers, 'remove', 'orphaned')

    else:
        containers = client.containers.list(all=True, filters={"label": "flask_app=spawned_container", "status": "running"})
        remove_or_stop_containers(containers, 'stop')

    app.logger.info("Cleanup complete.")


## ROUTES (FOR RENDERING HTML PAGES) ##
@app.route('/')
def INDEX_PAGE_ROUTE(): # default/home page route
    return render_template('index.html')


@app.route('/configure')
def CONFIGURE_PAGE_ROUTE():
    return render_template('configure.html')


## ROUTES (FOR HANDLING AJAX REQUESTS) ##
@app.route('/get_machine_info')
def GET_MACHINE_INFO_ROUTE():
    return jsonify(session.get('machine_info', []))


@app.route('/spawn', methods=['POST'])
def SPAWN_MACHINES_ROUTE():
    try:
        num_machines = request.form.get('num_machines', type=int)
        machine_info = session.get('machine_info', []) # track spawned containers
        spawned_machine_count = len(client.containers.list(filters={"label": "flask_app=spawned_container"}))

        if num_machines > MAX_CONTAINER_LIMIT - spawned_machine_count:
            return jsonify({"error": f"Cannot spawn more than {MAX_CONTAINER_LIMIT} machines."}), 400

        public_key = ensure_ssh_key()

        for _ in range(num_machines):
            container = spawn_container(public_key)                
            host_port = get_port_mapping(container)
            machine_info.append({
                'container_id': container.id[:12],
                'host_port': host_port,
                'host_command': f"ssh -o StrictHostKeyChecking=no -i {ssh_key_path} root@localhost -p {host_port}",
                'ssh_status': 'Ready'
            })

        session['machine_info'] = machine_info
        return jsonify(machine_info)

    except Exception as e:
        app.logger.error(f"Error in spawn_machines: {str(e)}")
        return jsonify({"error": str(e)}), 500


@app.route('/logs')
def DISPLAY_LOGS_ROUTE():
    """
    Display system and machine monitoring logs.
    Handles both single container and all container views.
    Includes error handling and logging capabilities.
    """
    try:
        # Get session data and query parameters
        machine_info = session.get('machine_info', [])
        selected_container = request.args.get('container_id')
        selected_tab = request.args.get('tab', 'system')

        app_logs = []
        machine_logs = {}

        # Read application logs
        try:
            with open('app.log', 'r') as f:
                app_logs = [line.strip() for line in f.readlines()]
                app_logs.reverse()  # Show newest logs first
        except FileNotFoundError:
            app.logger.warning("Application log file not found")
            app_logs = ["No application logs available"]
        except Exception as e:
            app.logger.error(f"Error reading application logs: {str(e)}")
            app_logs = [f"Error reading logs: {str(e)}"]

        # If a container is selected, fetch machine logs
        if selected_container:
            try:
                # Define monitoring paths for different log types
                monitoring_paths = {
                    'CPU Usage': '/var/log/infrastructure_monitoring/cpu_usage.log',
                    'Memory Usage': '/var/log/infrastructure_monitoring/memory_usage.log',
                    'Disk Usage': '/var/log/infrastructure_monitoring/disk_usage.log',
                    'Network Stats': '/var/log/infrastructure_monitoring/network.log',
                    'System Load': '/var/log/infrastructure_monitoring/load.log',
                    'Process List': '/var/log/infrastructure_monitoring/processes.log',
                    'System Updates': '/var/log/infrastructure_monitoring/updates.log',
                    'Security Alerts': '/var/log/infrastructure_monitoring/security.log'
                }

                # Select containers to monitor
                if selected_container == 'all':
                    containers_to_check = machine_info
                else:
                    containers_to_check = [m for m in machine_info if m['container_id'] == selected_container]

                if not containers_to_check:
                    raise ValueError(f"No containers found matching ID: {selected_container}")

                # Prepare Ansible inventory for selected containers
                inventory = {
                    f"container_{machine['container_id']}": {
                        "ansible_host": "localhost",
                        "ansible_port": machine['host_port'],
                        "ansible_user": "root",
                        "ansible_ssh_private_key_file": ssh_key_path,
                        "ansible_ssh_extra_args": "-o StrictHostKeyChecking=no"
                    }
                    for machine in containers_to_check
                }

                # Fetch logs for each monitoring type
                for log_name, log_path in monitoring_paths.items():
                    app.logger.debug(f"Fetching {log_name} logs from path: {log_path}")
                    
                    playbook_content = f'''
                    - name: Fetch {log_name} logs
                      hosts: all
                      tasks:
                        - name: Check if log file exists
                          stat:
                            path: {log_path}
                          register: log_file

                        - name: Read log file if it exists
                          command: "tail -n 50 {log_path}"
                          register: log_content
                          when: log_file.stat.exists
                          ignore_errors: yes

                        - name: Set default message if file doesn't exist
                          set_fact:
                            log_content:
                              stdout: "No {log_name} logs available"
                          when: not log_file.stat.exists
                    '''
                    
                    # Create temporary playbook file
                    playbook_file = create_temp_file(playbook_content, '.yml')
                    
                    try:
                        # Run Ansible playbook and get results
                        results = run_ansible(inventory, f"cat {log_path}")
                        
                        # Process results for each container
                        for container_id, content in results.items():
                            machine_id = container_id.split('_')[1]  # Extract container ID
                            
                            if machine_id not in machine_logs:
                                machine_logs[machine_id] = {}
                            
                            # Split log content into lines and clean up
                            log_entries = content.strip().split('\n') if content else ["No logs available"]
                            machine_logs[machine_id][log_name] = [
                                entry.strip() for entry in log_entries if entry.strip()
                            ]

                    except Exception as e:
                        app.logger.error(f"Error fetching {log_name} logs: {str(e)}")
                        if selected_container != 'all':
                            machine_logs[selected_container] = {
                                log_name: [f"Error fetching logs: {str(e)}"]
                            }
                    finally:
                        cleanup_files([playbook_file])

            except Exception as e:
                app.logger.error(f"Error processing machine logs: {str(e)}")
                return render_template(
                    'logs.html',
                    error=f"Error processing machine logs: {str(e)}",
                    app_logs=app_logs,
                    machine_logs={},
                    machine_info=machine_info,
                    selected_container=selected_container,
                    selected_tab=selected_tab
                )

        # Render template with all gathered logs
        return render_template(
            'logs.html',
            app_logs=app_logs,
            machine_logs=machine_logs,
            machine_info=machine_info,
            selected_container=selected_container,
            selected_tab=selected_tab,
            error=None
        )

    except Exception as e:
        app.logger.error(f"Unexpected error in display_logs: {str(e)}")
        return render_template(
            'logs.html',
            error=f"Unexpected error: {str(e)}",
            app_logs=["Error loading logs"],
            machine_logs={},
            machine_info=machine_info,
            selected_container=selected_container,
            selected_tab=selected_tab
        )


@app.route('/run_command', methods=['POST'])
def RUN_COMMAND_ROUTE():
    try:
        command = request.form['command']
        if not command: # [IMPROVEMENT] ensure that command text-box can accept multi-line commands & also accepts: ". / | & {} () etc" 
            return jsonify({"error": "Invalid command."}), 400

        machine_info = session.get('machine_info', [])
        if not machine_info:
            return jsonify({"error": "No machines spawned. Please spawn machines first."}), 400

        ansible_hosts = {
            f"container_{machine['container_id']}": {
                "ansible_host": "localhost",
                "ansible_port": machine['host_port'],
                "ansible_user": "root",
                "ansible_ssh_private_key_file": ssh_key_path,
                "ansible_ssh_extra_args": "-o StrictHostKeyChecking=no"
            }
            for machine in machine_info # if machine['ssh_status'] == 'Ready' # [NOTE] ssh_status not reliable as currently only ready machines are considered 
        }

        # if not ansible_hosts: # [OPTIONAL] depends on ssh_status check
        #     return jsonify({"error": "No ready containers available for command execution."}), 400

        app.logger.info("Running Ansible command on hosts.")
        command_results = run_ansible(ansible_hosts, command)

        for machine in machine_info:
            container_id = f"container_{machine['container_id']}"
            machine['command_result'] = command_results.get(container_id, "N/A (No result)")

        return jsonify(machine_info)

    except Exception as e:
        app.logger.error(f"Error running command: {str(e)}")
        return jsonify({"error": str(e)}), 500


@app.route('/<action>_all_containers', methods=['POST'])
def STOP_OR_REMOVE_ALL_CONTAINERS_ROUTE(action):
    try:
        if not session.get('machine_info'): # safeguard against empty session data
            return jsonify({"error": f"No machines spawned. Nothing to {action}."}), 400

        if action not in ['stop', 'remove']: # [OPTIONAL] validate the action parameter
            return jsonify({"error": f"Invalid action: {action}. Use 'stop' or 'remove'."}), 400

        cleanup(action)
        session['machine_info'] = []  # clear session data (for spawned containers)
        return jsonify({"status": f"All containers stopped {'and removed' if action == 'remove' else ''} successfully."})

    except Exception as e:
        app.logger.error(f"Error {'stopping' if action == 'stop' else 'removing' } all containers: {str(e)}")
        return jsonify({"error": str(e)}), 500


@app.route('/<action>_container', methods=['POST'])
def STOP_OR_REMOVE_CONTAINER_ROUTE(action):
    try:
        container_id = request.form.get('container_id')
        if not container_id:
            return jsonify({"error": "No container ID provided."}), 400
        
        if action not in ['stop', 'remove']: # [OPTIONAL] check for valid action
            return jsonify({"error": f"Invalid action: {action}. Use 'stop' or 'remove'."}), 400

        container = client.containers.get(container_id)
        remove_or_stop_containers([container], action)

        # remove the stopped/removed container from the session data
        session['machine_info'] = [machine for machine in session.get('machine_info', []) if machine['container_id'] != container_id]

        return jsonify({"status": f"Container {container_id[:12]} stopped {'and removed' if action == 'remove' else ''} successfully."})

    except docker.errors.NotFound: # invalid container id case
        return jsonify({"error": f"Container {container_id[:12]} not found."}), 404

    except Exception as e:
        app.logger.error(f"Error {'stopping' if action == 'stop' else 'removing' } container {container_id[:12]}: {str(e)}")
        return jsonify({"error": str(e)}), 500


@app.route('/fetch_stopped_containers', methods=['POST'])
def FETCH_STOPPED_CONTAINERS_ROUTE():
    try:
        containers = set(client.containers.list(all=True, filters={"label": "flask_app=spawned_container", "status": "exited"}))
        if not containers:
            return jsonify({"error": "No stopped containers found."}), 400
        
        machine_info = session.get('machine_info', [])
        if machine_info: # fetch only those containers that are not present in session data, [NOTE] O(N^2) operation reduced to O(N)
            containers -= set(client.containers.get(machine['container_id']) for machine in machine_info)

        for container in containers:
            try:
                container.start() # restart container
                host_port = get_port_mapping(container)
                machine_info.append({
                    'container_id': container.id[:12],
                    'host_port': host_port,
                    'host_command': f"ssh -o StrictHostKeyChecking=no -i {ssh_key_path} root@localhost -p {host_port}",
                    'ssh_status': 'Ready'
                })
                app.logger.info(f"Container {container.id[:12]} restarted successfully on port {host_port}")
            
            except Exception as e:
                app.logger.error(f"Error restarting container {container.id[:12]}: {str(e)}")

        session['machine_info'] = machine_info
        return jsonify(machine_info)
    
    except Exception as e:
        app.logger.error(f"Error fetching stopped containers: {str(e)}")
        return jsonify({"error": str(e)}), 500


@app.route('/save_config', methods=['POST'])
def SAVE_CONFIG_ROUTE(): # [NOTE] needs testing, [IMPROVEMENT] refactor or split into separate routes for each config option & add error handling
    config_option = request.form.get('configOption')
    if config_option == 'nginx':
        nginx_port = request.form.get('nginxPort')
        nginx_server_name = request.form.get('nginxServerName')

        # Save nginx configuration
        config = {
            'nginx_port': nginx_port,
            'server_name': nginx_server_name
        }
        with open('nginx_config.yml', 'w') as f:
            yaml.dump(config, f)

        # Get the list of spawned containers
        machine_info = session.get('machine_info', [])
        if not machine_info:
            return jsonify({"message": "No machines spawned. Please spawn machines first."})

        # Create a temporary inventory file
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.yml') as temp_inventory:
            inventory = {
                'all': {
                    'hosts': {}
                }
            }
            for machine in machine_info:
                inventory['all']['hosts'][f"container_{machine['container_id']}"] = {
                    'ansible_host': 'localhost',
                    'ansible_port': machine['host_port'],
                    'ansible_user': 'root',
                    'ansible_ssh_private_key_file': '/root/.ssh/docker_container_key',
                    'ansible_ssh_extra_args': '-o StrictHostKeyChecking=no'
                }
            yaml.dump(inventory, temp_inventory)

        # Run Ansible playbook
        playbook_path = os.path.join(os.path.dirname(__file__), 'playbooks', 'install_nginx.yml')
        result = ansible_runner.run(
            playbook=playbook_path,
            inventory=temp_inventory.name,
            extravars=config
        )

        # Clean up the temporary inventory file
        os.unlink(temp_inventory.name)

        if result.rc == 0:
            return jsonify({"message": "Nginx configuration saved and applied successfully."})
        else:
            return jsonify({"message": f"Error applying Nginx configuration. Return code: {result.rc}. Check Ansible logs for details."})

    elif config_option == 'ftp':
        try:
            ftp_port = request.form.get('ftpPort', '21')
            ftp_username = request.form.get('ftpUsername')
            ftp_password = request.form.get('ftpPassword')

            if not all([ftp_username, ftp_password]):
                return jsonify({"message": "Missing required FTP configuration parameters."}), 400

            # Save FTP configuration
            config = {
                'ftp_port': ftp_port,
                'ftp_username': ftp_username,
                'ftp_password': ftp_password
            }
            
            # Get the list of spawned containers
            machine_info = session.get('machine_info', [])
            if not machine_info:
                return jsonify({"message": "No machines spawned. Please spawn machines first."}), 400

            # Create temporary inventory file
            inventory_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.yml')
            try:
                inventory = {
                    'all': {
                        'hosts': {}
                    }
                }
                for machine in machine_info:
                    inventory['all']['hosts'][f"container_{machine['container_id']}"] = {
                        'ansible_host': 'localhost',
                        'ansible_port': machine['host_port'],
                        'ansible_user': 'root',
                        'ansible_ssh_private_key_file': ssh_key_path,
                        'ansible_ssh_extra_args': '-o StrictHostKeyChecking=no'
                    }
                yaml.dump(inventory, inventory_file)
                inventory_file.close()

                # Run Ansible playbook
                playbook_path = os.path.join(os.path.dirname(__file__), 'playbooks', 'install_ftp.yml')
                result = ansible_runner.run(
                    playbook=playbook_path,
                    inventory=inventory_file.name,
                    extravars=config,
                    private_data_dir=os.path.dirname(playbook_path)  # set private_data_dir to playbooks directory
                )
                
                if result.rc == 0:
                    return jsonify({
                        "message": "FTP configuration saved and applied successfully.",
                        "details": f"You can now connect to FTP using the configured username ({ftp_username}) and password on port {ftp_port}."
                    })
                else:
                    return jsonify({
                        "message": f"Error applying FTP configuration. Return code: {result.rc}. Check Ansible logs for details."
                    }), 500

            finally:
                # Clean up temporary inventory file
                if os.path.exists(inventory_file.name):
                    os.unlink(inventory_file.name)

        except Exception as e:
            app.logger.error(f"Error configuring FTP: {str(e)}")
            return jsonify({"message": f"Error configuring FTP: {str(e)}"}), 500

    elif config_option == 'custom':
        if 'customPlaybook' not in request.files:
            app.logger.error("No custom playbook file provided")
            return jsonify({"message": "No custom playbook file provided."}), 400
    
        custom_playbook = request.files['customPlaybook']
        if custom_playbook.filename == '':
            app.logger.error("No selected file")
            return jsonify({"message": "No selected file."}), 400

        if custom_playbook and custom_playbook.filename.endswith(('.yml', '.yaml')):
            try:
                # Save the custom playbook to a temporary file
                with tempfile.NamedTemporaryFile(mode='w+', suffix='.yml', delete=False) as temp_playbook:
                    custom_playbook.save(temp_playbook.name)

                # Get the list of spawned containers
                machine_info = session.get('machine_info', [])
                if not machine_info:
                    app.logger.error("No machines spawned")
                    return jsonify({"message": "No machines spawned. Please spawn machines first."}), 400

                # Create a temporary inventory file
                with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.yml') as temp_inventory:
                    inventory = {
                        'all': {
                            'hosts': {}
                        }
                    }
                    for machine in machine_info:
                        inventory['all']['hosts'][f"container_{machine['container_id']}"] = {
                            'ansible_host': 'localhost',
                            'ansible_port': machine['host_port'],
                            'ansible_user': 'root',
                            'ansible_ssh_private_key_file': ssh_key_path,
                            'ansible_ssh_extra_args': '-o StrictHostKeyChecking=no'
                        }
                    yaml.dump(inventory, temp_inventory)

                # Run Ansible playbook
                app.logger.info(f"Running custom playbook: {temp_playbook.name}")
                result = ansible_runner.run(
                    playbook=temp_playbook.name,
                    inventory=temp_inventory.name,
                    extravars={'ansible_ssh_private_key_file': ssh_key_path},
                    verbosity=2
                )

                # Clean up temporary files
                os.unlink(temp_playbook.name)
                os.unlink(temp_inventory.name)

                if result.rc == 0:
                    app.logger.info("Custom playbook executed successfully")
                    return jsonify({"message": "Custom playbook executed successfully."})
                else:
                    app.logger.error(f"Error executing custom playbook. Return code: {result.rc}")
                    return jsonify({"message": f"Error executing custom playbook. Return code: {result.rc}. Check Ansible logs for details."}), 500

            except Exception as e:
                app.logger.error(f"Error executing custom playbook: {str(e)}")
                return jsonify({"message": f"Error executing custom playbook: {str(e)}"}), 500

        else:
            app.logger.error("Invalid file format")
            return jsonify({"message": "Invalid file format. Please upload a YAML file."}), 400

    else:
        return jsonify({"message": "Invalid configuration option."})
    


## [NOTE] SOME IMPORTANT POINTS (FOR ROUTES): ##
# 1) axios/fetch is used for making AJAX requests (in the frontend)
# 2) all API routes return JSON responses (for AJAX requests)
# 3) HTTP status codes are used to indicate success/failure of requests:
#    e.g. 200 (OK -> default), 400 (Bad Request), 404 (Not Found), 500 (Internal Server Error)
# 4) axios is much consice & easier to use than fetch, but fetch API is more powerful & flexible


## EXIT POINT SETUP (FOR CLEANUP) ##
atexit.register(cleanup) #  register 'cleanup' to run when the app quits normally

def handle_sigint(signum, frame):
    """Custom signal handler to catch Ctrl+C (SIGINT) interrupts."""
    app.logger.info("Received SIGINT (Ctrl+C), cleaning up...")
    exit(0) # also calls the 'cleanup' function

def handle_sigstp(signum, frame):
    """Custom signal handler to catch SIGTSTP (Ctrl+Z) interrupts."""
    app.logger.info("Received SIGTSTP (Ctrl+Z), cleaning up...")
    exit(0)

def handle_sigterm(signum, frame):
    """Custom signal handler to catch SIGTERM interrupts."""
    app.logger.info("Received SIGTERM, cleaning up...")
    exit(0)

signal.signal(signal.SIGINT, handle_sigint) # register SIGINT custom handler to run when Ctrl+C is pressed
signal.signal(signal.SIGTSTP, handle_sigstp) # register SIGTSTP custom handler to run when Ctrl+Z is pressed
signal.signal(signal.SIGTERM, handle_sigterm) # register SIGTERM custom handler to run when the app is terminated


## MAIN ENTRY POINT ##
if __name__ == '__main__':
    app.run(debug=True, use_reloader=False) # start the Flask app in debug mode (with auto-reload disabled)
